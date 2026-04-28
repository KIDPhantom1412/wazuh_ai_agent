import json
import logging
import re
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from .log_retrieval_helper import get_archives_by_eventid, get_archives_by_keyword
from .prompt import attribution_investigation_prompt_long
from .state import AttributionPlannerActionCommand, AttributionState
from .utils import load_mitre, load_skill

# from .utils import extract_agent_ip_mapping

logger = logging.getLogger(__name__)

CURRENT_DIR = Path(__file__).parent
SKILL_FILE_PATH = (
    CURRENT_DIR.parent.parent / "documents" / "skill" / "attribution_skills" / "report_format.md"
)
MITRE_KB_FILE_PATH = (
    CURRENT_DIR.parent.parent
    / "documents"
    / "skill"
    / "attribution_skills"
    / "mitre_knowledgebase.md"
)


class SynthesizedFindings(BaseModel):
    task_description: str = Field(
        description="Briefly restate the exact investigation instruction you are executing (e.g., 'Downward tracking of PID 10484 on Agent 005 for Process Creation'). DO NOT include any prefixes or markdown headers. Must be in Chinese."
    )
    detailed_findings: str = Field(
        description="""A strict chronological timeline and factual summary of the events.
        CRITICAL ZERO-LOSS RULE: You MUST embed all exact technical Evidence/IOCs directly into this narrative.
        Whenever you mention an event, you MUST include its exact timestamp, exact PID, full absolute file path, unredacted command line, and any related IPs/Ports.

        ### ANTI-HALLUCINATION PROTOCOL (CRITICAL) ###
        1. GROUNDING RULE: You are STRICTLY FORBIDDEN from inventing, inferring, or generating ANY data (timestamps, PIDs, IPs, filenames, actions) that is not EXPLICITLY present in the provided Raw JSON Logs.
        2. MISSING EVIDENCE RULE: If the Raw Logs do NOT contain the exact behavior requested in the instruction (e.g., the instruction asks for Process Creation, but logs only show File Creation), you MUST explicitly state the discrepancy.
        3. NULL RESPONSE RULE: If the Raw Logs are empty, irrelevant, or insufficient to fulfill the instruction, you MUST output EXACTLY: "日志检索结果未包含符合预期的行为证据。发现的孤立事件为：[简述实际发现的内容]。" DO NOT fabricate a story.

        ROLE BOUNDARY (CRITICAL): You are a Fact Extractor, NOT the final judge. DO NOT forcefully assign MITRE Tactic IDs unless explicitly supported by the 'MITRE Knowledge'. If in doubt, just describe the objective behavior.
        FORMATTING RULE: DO NOT output any title or markdown headers. Just output the pure paragraph content. Must be affirmatively stated in Chinese."""
    )


"""
Nodes:
0. Decision_Node
1. Attribution_Planner_Node
2. Log_Retrieval_Node
3. Information_Synthesizer_Node
4. MITRE_Expert_Node - optional
5. Reporter_Node
6. User_Input_Node
"""


def decision_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 0: Decision Node (The Brain for Initialization)."""
    logger.info("Executing Decision Node...")

    is_clue_confirmed = state.get("is_clue_confirmed")
    requires_mitre_kb = state.get("requires_mitre_kb")
    investigation_clue = state.get("investigation_clue")
    pending_type = state.get("pending_question_type")
    messages = state.get("messages", [])
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    multi_host_updates = {}
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}
    # if is_multi_host is None:
    #     agent_ip_mapping = extract_agent_ip_mapping()
    #     is_multi_host = len(agent_ip_mapping) > 1
    # if is_multi_host and not agent_ip_mapping:
    #     agent_ip_mapping = extract_agent_ip_mapping()
    #
    # multi_host_updates = {
    #     "is_multi_host": is_multi_host,
    #     "agent_ip_mapping": agent_ip_mapping,
    # }

    last_message = messages[-1] if messages else None
    is_human = last_message.type == "human" if last_message else False
    user_text = last_message.content if is_human else ""

    if not is_clue_confirmed:
        if not investigation_clue:
            # 判断是原始日志还是现成线索
            logger.info("Phase 1: Analyzing initial input...")
            system_prompt = """
            You are a Cybersecurity Triage Expert.
            Analyze the user's input: is it a raw JSON/System log, or a clear natural language attack clue?

            [CRITERIA]
            A "clear natural language attack clue" typically describes an alert, the compromised agent, the malicious behavior, and a strict time boundary.
            Example of a valid clue: "Agent 012 触发了 Level 14 的告警（Rule 61532: Suspicious PowerShell execution）。告警显示进程 powershell.exe (PID 5192) 异常执行了编码命令，并在 Public 目录下释放了 payload.exe。请启动攻击溯源调查。时间范围限定在北京时间的 2026年3月25日的 14:10 到 14:20 之间。"

            [INSTRUCTIONS]
            1. If it is ALREADY a clear natural language clue, output exactly 'READY'.
            2. If it is a raw log, extract core entities (Agent ID, Rule, PID, File, Time) and rewrite it into a professional attack clue in Chinese. Output ONLY the new clue. Do NOT output 'READY'.
            3. TIME WINDOW & ZONE RULE (CRITICAL):
               When generating the time boundary from a raw log, you MUST perform the following steps exactly:
               - (Timezone Normalization): Normalize the raw log timestamp into Beijing Time (UTC+8). If the log is in UTC (e.g., ends with 'Z'), you must manually add 8 hours. If it already contains "+0800" or lacks a timezone, treat it as Beijing Time.
               - (Window Calculation): Create a 10-minute investigation window centered around this normalized Beijing Time. Calculate the start time by subtracting 5 minutes, and the end time by adding 5 minutes. (For example, if the log's actual time is 10:16:35, your time boundary MUST be from 10:11:35 to 10:21:35).
               - (Formatting): In ALL cases, you MUST explicitly append "（北京时间）" to the final time boundary in your generated clue.
            4. Output ONLY the newly generated clue. Do NOT output 'READY' if you generated a clue.

            """

            prompt = ChatPromptTemplate.from_messages(
                [("system", system_prompt), ("human", "{user_text}")]
            )
            result = (prompt | model).invoke({"user_text": user_text})
            analysis = result.content.strip()

            if analysis == "READY":
                return {
                    **multi_host_updates,
                    "investigation_clue": user_text,
                    "is_clue_confirmed": True,
                    "next_action_fromDecisionNode": {"target": "Decision_Node"},
                    "next_action_fromAttributionPlannerNode": None,
                }
            else:
                return {
                    **multi_host_updates,
                    "investigation_clue": analysis,
                    "pending_question_type": "CLUE",
                    "next_action_fromDecisionNode": {
                        "target": "User_Input_Node",
                        "instruction": "ASK_CLUE",
                    },
                    "next_action_fromAttributionPlannerNode": None,
                }
        else:
            # 线索已存在，大模型判断用户的回复是同意还是要求修改
            if is_human and pending_type == "CLUE":
                logger.info("Phase 1: Parsing user feedback on clue...")
                system_prompt = """You are an intent parsing and rewriting assistant.
                Evaluate the user's feedback regarding the 'Original Clue'.
                1. If user agrees/confirms (e.g., '是', 'yes', '确认', 'ok'), output exactly 'AGREE'.
                2. If user wants to modify, rewrite the clue COMPLETELY incorporating their feedback. Output ONLY the new revised clue.

                [CRITICAL REWRITE RULES]
                - ZERO DATA LOSS: You MUST preserve all original details (Agent ID, Rule, PID, filenames, etc.) that the user did NOT ask to change.
                - NO DELTA OUTPUT: Do NOT just output the user's modifications. You MUST output the full, standalone, readable revised clue.
                - NO FILLER: Output ONLY the final revised clue text. Do not add phrases like "已修改：" or "Here is the revised clue:".

                [CONTEXT]
                Original Clue:
                {clue}
                """

                prompt = ChatPromptTemplate.from_messages(
                    [("system", system_prompt), ("human", "{user_text}")]
                )
                result = (prompt | model).invoke(
                    {"clue": investigation_clue, "user_text": user_text}
                )
                intent = result.content.strip()

                if intent.upper() == "AGREE":
                    return {
                        **multi_host_updates,
                        "is_clue_confirmed": True,
                        "pending_question_type": None,
                        "next_action_fromDecisionNode": {"target": "Decision_Node"},
                        "next_action_fromAttributionPlannerNode": None,
                    }
                else:
                    return {
                        **multi_host_updates,
                        "investigation_clue": intent,
                        "next_action_fromDecisionNode": {
                            "target": "User_Input_Node",
                            "instruction": "ASK_CLUE_MODIFIED",
                        },
                        "next_action_fromAttributionPlannerNode": None,
                    }

    if is_clue_confirmed and requires_mitre_kb is None:
        return {
            **multi_host_updates,
            "requires_mitre_kb": True,
            "pending_question_type": None,
            "messages": [AIMessage(content="开启 MITRE 专家知识库辅助攻击溯源调查...")],
            "next_action_fromDecisionNode": {"target": "Attribution_Planner_Node"},
            "next_action_fromAttributionPlannerNode": None,
        }
        # if is_human and pending_type == "MITRE":
        #     logger.info("Phase 2: Parsing MITRE response...")
        #     system_prompt = "Analyze if user agreed (YES) or declined (NO). Chinese '是/开启' = YES, '否/关闭/不用' = NO. Output strictly 'YES' or 'NO'."
        #     prompt = ChatPromptTemplate.from_messages(
        #         [("system", system_prompt), ("human", "{user_text}")]
        #     )
        #     result = (prompt | model).invoke({"user_text": user_text})
        #     intent = result.content.strip().upper()

        #     if "YES" in intent:
        #         return {
        #             "requires_mitre_kb": True,
        #             "pending_question_type": None,
        #             "messages": [AIMessage(content="已开启 MITRE 专家知识库，正在为您深入调查...")],
        #             "next_action": {"target": "Decision_Node"},
        #         }
        #     else:
        #         return {
        #             "requires_mitre_kb": False,
        #             "pending_question_type": None,
        #             "messages": [
        #                 AIMessage(content="已关闭 MITRE 专家知识库，将仅根据日志事实进行排查...")
        #             ],
        #             "next_action": {"target": "Decision_Node"},
        #         }
        # else:
        #     return {
        #         "pending_question_type": "MITRE",
        #         "next_action": {"target": "User_Input_Node", "instruction": "ASK_MITRE"},
        #     }

    logger.info("Initialization complete. Routing to Attribution Planner Node.")
    return {
        **multi_host_updates,
        "next_action_fromDecisionNode": {"target": "Attribution_Planner_Node"},
        "next_action_fromAttributionPlannerNode": None,
    }


def attribution_planner_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """
    Node 1: Attribution Planner Node.
    """
    logger.info("Executing Attribution Planner Node")

    use_mitre = state.get("requires_mitre_kb")
    state.get("investigation_clue", "未提供有效初始线索")

    messages = state.get("messages", [])
    mitre_kb = state.get("mitre_knowledge_base", {})
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}
    # agent_ip_mapping_str = (
    #     json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2) if agent_ip_mapping else "{}"
    # )

    attribution_investigation_prompt: str = attribution_investigation_prompt_long

    try:
        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】\n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No external knowledge retrieved yet."
        # kb_str = (
        #     json.dumps(mitre_kb, ensure_ascii=False, indent=2)
        #     if mitre_kb
        #     else "No external knowledge retrieved yet."
        # )
    except Exception as e:
        logger.error("Error formatting state context: %s", e)
        kb_str = str(mitre_kb)

    mitre_instructions = ""
    if use_mitre:
        mitre_instructions = """
  - 'MITRE_Expert_Node': Routes to a knowledge base to retrieve specific MITRE ATT&CK technique details.
  - **How to instruct**: Explicitly mention the MITRE ATT&CK ID (e.g., T1059 or T1003.001) in your instruction.
  - **Rule 1 (Explicit SIEM Tags)**: Whenever you encounter a MITRE ATT&CK ID in a raw log's `rule.mitre.id` field, you MUST call this node using that ID, UNLESS it has already been queried.
  - **Rule 2 (Implicit Behaviors - CRITICAL)**: While SIEM labels provide a useful baseline, they can sometimes be incomplete or false positives. You MUST proactively analyze process names, command-line arguments, and systemic behaviors. Use your cybersecurity expertise to independently deduce the true underlying attack techniques and query this node for them, UNLESS they have already been queried.
  - **Rule 3 (Deduplication & State Awareness - ABSOLUTE MANDATORY)**: Before routing to this node, you MUST check the **MITRE Knowledge Base** section at the bottom of this prompt. If the TID you intend to query is ALREADY listed there, you are STRICTLY FORBIDDEN from calling this node for that exact TID again.
"""

    multi_host_instructions = ""
    # if is_multi_host:
    #     multi_host_instructions = f"""
    #
    # ### MULTI-HOST MODE
    # Agent ID -> IP Mapping (JSON):
    # {agent_ip_mapping_str}
    #
    # Rules:
    # 1. If you need to pivot by an IP address and that IP exists in the mapping, you MUST translate it into the corresponding Agent ID and query that Agent ID.
    # 2. If you see evidence that "Agent A" interacted with "IP B" and IP B maps to "Agent B", you MUST pivot and query Agent B in a subsequent step (do NOT stop after only querying Agent A).
    # 3. You MUST NOT create dead loops. At most one cross-host pivot per planning turn.
    # """

    system_prompt = (
        """You are an elite Cybersecurity Chief Attribution Planner.
Your role is to orchestrate a complex attack forensics investigation. You do NOT query databases directly. Instead, you analyze the intelligence gathered so far and delegate specific tasks to specialized subordinate nodes.

## YOUR ARSENAL (TARGET NODES)
- 'Log_Retrieval_Node': Routes to a specialized AI agent equipped with Wazuh API tools.
  - **How to instruct**: Provide clear, natural language instructions detailing *what* you want to find. You MUST explicitly mention *the Agent ID* in your instruction.
  - *Example*: "Investigate PID 6536 on Agent 005 for lateral activities, specifically focusing on File Drops. Apply time range 2026-03-25T10:00:00Z to 2026-03-25T11:00:00Z."
  - IMPORTANT: The Log_Retrieval_Node will execute exactly what you ask. It will NOT automatically translate IP addresses into Agent IDs for you.

- 'Reporter_Node': Routes to the reporting engine to close the case.
  - When to use (STRICT EXHAUSTION TEST): You are STRICTLY FORBIDDEN from choosing this node until you have exhaustively investigated EVERY SINGLE suspicious PID discovered. Review your history: if there is any PID where you haven't checked BOTH its origins (Upward trace) AND its subsequent actions (Downward/Lateral trace), you MUST go back and query it. Choose this ONLY when you have fully exhausted all leads, built a complete causal tree, and have enough evidence.
  - **How to instruct**: Provide a brief draft/summary of the attack narrative for the reporter to expand upon.

{mitre_instructions}
{multi_host_instructions}

"""
        + attribution_investigation_prompt
        + """

### CURRENT CASE CONTEXT

- **MITRE Knowledge Base**:
{kb_str}
"""
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    parser = PydanticOutputParser(pydantic_object=AttributionPlannerActionCommand)
    format_instructions = parser.get_format_instructions()

    try:
        llm_msg = (prompt | model).invoke(
            {
                "messages": messages,
                "mitre_instructions": mitre_instructions,
                "multi_host_instructions": multi_host_instructions,
                "kb_str": kb_str,
                "format_instructions": format_instructions,
            }
        )

        raw_text = getattr(llm_msg, "content", str(llm_msg))

        try:
            result = parser.parse(raw_text)
        except Exception as parse_e:
            logger.warning(
                "Planner initial parsing failed, triggering repair mechanism. Error: %s", parse_e
            )

            repair_prompt = ChatPromptTemplate.from_messages(
                [
                    (
                        "system",
                        "Convert the input into exactly one valid JSON object matching this schema.\n"
                        "CRITICAL OVERRIDE: You MUST NOT wrap the result in a 'properties' dictionary. Return the flat object directly.\n"
                        "{format_instructions}",
                    ),
                    ("human", "{raw_text}"),
                ]
            )
            repaired = (repair_prompt | model).invoke(
                {"raw_text": raw_text, "format_instructions": format_instructions}
            )
            repaired_text = getattr(repaired, "content", str(repaired))
            result = parser.parse(repaired_text)

        logger.info("Planner decision successful. Target: %s", result.target)

        return {
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": {
                "target": result.target,
                "instruction": result.instruction,
            },
        }

    except Exception as final_e:
        logger.error("Error in attribution planner node: %s", final_e)
        return {"next_action_fromAttributionPlannerNode": None}


def log_retrieval_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 2: Log Retrieval Node"""
    logger.info("Executing Log Retrieval Node")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    if not next_action or next_action.get("target") != "Log_Retrieval_Node":
        logger.warning("Invalid route to Log Retrieval Node.")
        return {"current_raw_logs": [], "next_action_fromAttributionPlannerNode": None}

    instruction = next_action.get("instruction", "")

    tools = [get_archives_by_keyword, get_archives_by_eventid]

    system_prompt = """You are an elite Data Access & API Agent for the Wazuh Indexer.
Your primary role is to fetch precise security telemetry, logs, and forensic data using the provided tools. You act as the core data engine for other analytical agents and human users.

### TOOL SELECTION LOGIC (STRICT ADHERENCE):
- **Scenario A: Generic Keyword Searches (STRICTLY NON-PROCESS QUERIES)**
  If the instruction explicitly asks to search for a general text string, malicious filename, or IP address (e.g., "Search for mimikatz.exe"), you MUST call `get_archives_by_keyword`.
  *ABSOLUTE BAN (CRITICAL)*: You are STRICTLY FORBIDDEN from executing `get_archives_by_keyword` if the instruction requests tracking a numerical `PID` or specific behavior like "File Drops".

- **Scenario B: Specific Behaviors, Process Trees, Registry activity & Lateral Activity**
  If the instruction asks about process tracking, registry changes, or file actions, you MUST call `get_archives_by_eventid`.
  - To find the execution details of a process itself (e.g., finding its creation log), use `query_type="PROCESS_ID"` and `event_ids=["1"]`.
  - To find child processes spawned by a specific parent, use `query_type="PARENT_PROCESS_ID"` and `event_ids=["1"]`.
  - To find lateral activities: Use relevant `event_ids` (Network Connection=["3","4624"], DLL Loading=["7"], Injection=["8","10"], File Creation=["11"], Registry Modification=["12","13","14"], Service Installation=["7045"].).
  - **PATH Retry Rule (FILE & REGISTRY)**: If you execute a `FILE_PATH` or `REGISTRY_PATH` query using a full path and the tool returns a `search_feedback` error, you MUST automatically extract the last part of the path (the filename or the specific Key name) and execute a SECOND tool call using ONLY that fragment as the `query_value`.

### STRICT TOOL ISOLATION (NO FALLBACKS):
- **NO KEYWORD FALLBACK FOR PIDs**: If the specific process tracking tools return 0 results or a `search_feedback` message for a PID, you MUST simply return that result to the Chief Planner. **DO NOT** attempt to "help" by falling back to `get_archives_by_keyword` to search the PID as a keyword.


### API TRANSLATION RULES (CRITICAL)
When translating the Planner's instructions into API calls, you MUST adhere to these field mappings for EventID=1 (Process Creation):
1. **For 'Process Creation (Upward)'**: The Planner wants to know WHO created the target PID.
   - You must search for the log where the target PID is the NEW process being born.
   - Use `query_type="PROCESS_ID"` and pass the target PID. This returns the exact moment the process started, revealing its `parent_process_id` and `parent_image`.
2. **For 'Process Creation (Downward)'**: The Planner wants to know WHAT the target PID created.
   - You must search for logs where the target PID acted as the creator.
   - You MUST use `query_type="PARENT_PROCESS_ID"` and pass the target PID. This will return all child processes spawned by it.

### DATA HANDLING & ROLE BOUNDARIES (CRITICAL):
You are exclusively a raw data retrieval pipeline. You MUST adhere strictly to these constraints:
1. **ZERO HALLUCINATION**: You MUST NOT generate, simulate, or mock any JSON data.
2. **ZERO MODIFICATION**: When the tool returns the JSON logs, you MUST NOT summarize, filter, analyze, or explain them.
3. **NO RETRIES ON EMPTY DATA (ABSOLUTE RULE)**: You are a single-shot execution agent (except for the FILE_PATH retry rule above).
   - If `get_archives_by_eventid` returns a JSON indicating no logs were found (e.g., `{"search_feedback": ...}`), your job is DONE.
   - DO NOT remove or expand the time boundaries to search historical data.
   - IMMEDIATELY stop thinking and output the exact `search_feedback` message.
4. **RESPONSE FORMAT**:
   - **If data is found**: Respond with a brief confirmation (e.g., "Data successfully retrieved and passed to the next node.") and immediately stop. Leave all analysis to the Information Synthesizer node.
   - **If no data is found**: Output the `search_feedback` message and stop. Leave the tactical pivot decisions to the Chief Planner.
"""

    agent = create_agent(model, tools, system_prompt=system_prompt)

    logger.info("Dispatching task to Log Retrieval Agent...")
    raw_logs_buffer = []

    try:
        result = agent.invoke(
            {"messages": [("human", f"Chief Planner Instruction:\n{instruction}")]}
        )

        for msg in result["messages"]:
            if isinstance(msg, ToolMessage):
                try:
                    parsed_logs = json.loads(msg.content)

                    if isinstance(parsed_logs, list):
                        raw_logs_buffer.extend(parsed_logs)
                    elif isinstance(parsed_logs, dict) and "search_feedback" not in parsed_logs:
                        raw_logs_buffer.append(parsed_logs)
                    elif isinstance(parsed_logs, dict) and "search_feedback" in parsed_logs:
                        logger.info(
                            "Tool returned search feedback: %s", parsed_logs["search_feedback"]
                        )

                except json.JSONDecodeError:
                    logger.error(
                        "Failed to parse tool observation as JSON. Observation snippet: %s",
                        str(msg.content)[:100],
                    )

    except Exception as e:
        logger.error("Agent execution failed: %s", e)

    if raw_logs_buffer:
        logger.info("Log Retrieval successful. Captured %d raw logs.", len(raw_logs_buffer))
    else:
        logger.info("Log Retrieval returned 0 logs.")

    return {"current_raw_logs": raw_logs_buffer}


def information_synthesizer_node(
    state: AttributionState, config: RunnableConfig, model: BaseChatModel
):
    """Node 3: Information Synthesizer Node."""
    logger.info("Executing Information Synthesizer Node")

    raw_logs = state.get("current_raw_logs")
    next_action = state.get("next_action_fromAttributionPlannerNode")
    mitre_kb = state.get("mitre_knowledge_base", {})
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}

    instruction = (
        next_action.get("instruction", "未命名调查任务") if next_action else "未命名调查任务"
    )

    if not raw_logs:
        logger.info("No raw logs provided. Skipping synthesis.")
        failure_feedback = f"""
        针对指令”{instruction}』“的查询未返回任何日志数据，针对该特定维度的线索的查询可能不存在对应的日志。
        可尝试切换至其他行为类型或者查询条件进行查询日志， 以获取更多相关信息。
        """
        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=failure_feedback)],
        }

    try:
        logs_str = json.dumps(raw_logs[:20], ensure_ascii=False, indent=2)

        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】\n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No MITRE context available."
        # kb_str = (
        #     json.dumps(mitre_kb, ensure_ascii=False, indent=2)
        #     if mitre_kb
        #     else "No MITRE context available."
        # )
    except Exception as e:
        logger.error("Error formatting logs or KB: %s", e)
        logs_str = str(raw_logs[:20])
        kb_str = str(mitre_kb)

    parser = PydanticOutputParser(pydantic_object=SynthesizedFindings)
    format_instructions = parser.get_format_instructions()

    multi_host_instructions = ""
    # if is_multi_host:
    #     agent_ip_mapping_str = json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2)
    #     multi_host_instructions = f"""
    #
    # ### MULTI-HOST MODE (CRITICAL)
    # You MUST use the Agent ID -> IP mapping to translate IP addresses into Agent IDs when describing cross-host activity. If an IP appears in the logs and exists in the mapping, you MUST explicitly mention the mapped Agent ID.
    #
    # ### MULTI-HOST CONTEXT
    # - **Agent ID -> IP Mapping (JSON)**:
    # {agent_ip_mapping_str}
    # """

    system_prompt = """You are an elite Cybersecurity Information Synthesizer.
Your task is to exhaustively analyze raw JSON logs retrieved by the Data Agent, extract exact Indicators of Compromise (IOCs), and write a definitive tactical summary for the Chief Planner.

### YOUR INPUTS
1. **Original Instruction**: What the Data Agent was asked to look for.
2. **Raw JSON Logs**: The actual data retrieved from the SIEM.
3. **MITRE Knowledge Base**: Threat intelligence to help you correctly label attacker behaviors.

### CRITICAL RULES & STRICT OVERRIDES
1. **Comprehensive Expert Synthesis (Anti-Bias & Zero-Drop)**: Your final extraction MUST be exhaustive. You MUST explicitly include the events of ALL isolated artifacts verified during the hunt. Categorize every event using the precise technical definitions from the MITRE Expert Knowledge, strictly overriding any misleading or generic SIEM alert descriptions.
2. **CRITICAL TIME REQUIREMENT**: You MUST provide a strict chronological timeline in your summary. For EVERY single extracted evidence item, you MUST copy-paste its EXACT timestamp directly from the raw JSON logs (e.g., "2026-03-10T09:32:30.571Z"). Ensure zero temporal hallucinations.
3. **RAW EVIDENCE VAULT (ZERO-LOSS RULE - CRITICAL)**: You MUST NOT summarize away low-level technical evidence. Explicitly extract and preserve exact values, specifically including:
   - **Exact Parameters:** Explicit hex codes (e.g., 0x1f3fff), registry paths, or network ports.
   - **Complete Artifacts:** EVERY single file created or modified, including intermediate/temp files, with full absolute paths.
   - **Raw Execution:** Unredacted, complete command-line arguments and payloads. Do not truncate.
   - **Entity Identifiers:** Exact numerical PIDs, ProcessGuids, or IP addresses for all involved actors and victims.
   *NEVER generalize into vague actions like "accessed a process", "modified the registry", or "dropped files".*
4. **CONFIDENT EXPERT TONE**: When your investigation confirms an attack's execution, state the success affirmatively without using hedging language (e.g., avoid "possibly", "might have").
5. **LANGUAGE**: The `summary` field MUST be written in Chinese".

### Lineage-Based Handle Audit
When analyzing 0x1fffff (PROCESS_ALL_ACCESS) access masks, you must verify the process relationship. If the Source process is the Parent of the Target process (e.g., a shell managing child utilities), classify the event as "Normal child process management." Strictly avoid mischaracterizing this native Windows behavior as process injection, credential dumping, or unauthorized control.

### CONTEXT
- **Original Instruction**: {instruction}
- **MITRE Knowledge**:
{kb_str}
{multi_host_instructions}

{format_instructions}
"""

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "Here are the raw logs to analyze:\n```json\n{logs_str}\n```"),
        ]
    )

    try:
        logger.info("Synthesizing %d logs...", len(raw_logs))

        llm_msg = (prompt | model).invoke(
            {
                "instruction": instruction,
                "kb_str": kb_str,
                "multi_host_instructions": multi_host_instructions,
                "logs_str": logs_str,
                "format_instructions": format_instructions,
            }
        )

        raw_text = getattr(llm_msg, "content", str(llm_msg))

        try:
            result = parser.parse(raw_text)
        except Exception as parse_e:
            logger.warning(
                "Initial parsing failed, triggering repair mechanism. Error: %s", parse_e
            )

            repair_prompt = ChatPromptTemplate.from_messages(
                [
                    (
                        "system",
                        "Convert the input into exactly one valid JSON object matching this schema.\n"
                        "CRITICAL OVERRIDE: You MUST NOT wrap the result in a 'properties' dictionary. Return the flat object directly.\n"
                        "{format_instructions}",
                    ),
                    ("human", "{raw_text}"),
                ]
            )
            repaired_msg = (repair_prompt | model).invoke(
                {"raw_text": raw_text, "format_instructions": format_instructions}
            )
            repaired_text = getattr(repaired_msg, "content", str(repaired_msg))
            result = parser.parse(repaired_text)

        task_desc = getattr(result, "task_description", "未提取到指令")
        findings = getattr(result, "detailed_findings", "解析完成，未发现异常。")

        summary = f"【执行指令描述】\n{task_desc}\n\n【调查总结与IOC清单】\n{findings}"

        logger.info("Synthesis complete. Structured note generated.")

        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=summary)],
        }

    except Exception as e:
        logger.error("Error during synthesis (even after repair): %s", e)
        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "messages": [
                AIMessage(
                    content=f"[审查官汇报] 针对指令『{instruction}』的日志解析失败。异常信息: {e}"
                )
            ],
        }


def mitre_expert_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 4: MITRE Expert Node ."""
    logger.info("Executing MITRE Expert Node")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    instruction = next_action.get("instruction", "") if next_action else ""
    technique_ids = re.findall(r"T\d{4}(?:\.\d{3})?", instruction.upper())

    new_knowledge = {}
    existing_kb = state.get("mitre_knowledge_base", {})

    # 用于收集在循环中产生的每一条汇报足迹
    messages_to_append = []

    if not technique_ids:
        logger.warning("No MITRE ID found in the instruction: %s", instruction)
        messages_to_append.append(
            AIMessage(
                content="[MITRE Query Info] 指令中未包含有效的 Txxxx 编号，无法执行查询。请重新检查指令。"
            )
        )
    else:
        unique_ids = list(set(technique_ids))

        for tid in unique_ids:
            if tid in existing_kb:
                logger.info("MITRE ID %s is already in the global knowledge base. Skipping.", tid)
                messages_to_append.append(
                    AIMessage(
                        content=f"[MITRE Query Info] 战术 {tid} 已存在于底层知识库中，无需重复查询。"
                    )
                )
                continue

            logger.info("Obtaining knowledge from MITRE KB for: %s", tid)
            try:
                knowledge = load_mitre(MITRE_KB_FILE_PATH, tid)
                if knowledge:
                    new_knowledge[tid] = f"--- External Knowledge FOR {tid} ---\n{knowledge}"
                    messages_to_append.append(
                        AIMessage(
                            content=f"[MITRE Query Info] 已成功提取并加载战术 {tid} 的情报，底层知识库已更新。"
                        )
                    )
                else:
                    new_knowledge[tid] = (
                        f"No detailed expert guidelines found for {tid}. Please proceed using your general cybersecurity knowledge."
                    )
                    messages_to_append.append(
                        AIMessage(
                            content=f"[MITRE Query Info] 本地知识库中未找到战术 {tid} 的详细情报。"
                        )
                    )
            except Exception as e:
                logger.error("Error retrieving MITRE KB for %s: %s", tid, e)
                new_knowledge[tid] = f"Failed to retrieve knowledge for {tid} due to system error."
                messages_to_append.append(
                    AIMessage(content=f"[MITRE Query Info] 提取战术 {tid} 时发生系统级异常。")
                )

    if new_knowledge:
        logger.info("Successfully retrieved knowledge for %s techniques.", len(new_knowledge))

    return {
        "mitre_knowledge_base": new_knowledge,
        "next_action_fromAttributionPlannerNode": None,
        "messages": messages_to_append,
    }


def reporter_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 5: Reporter Node."""
    logger.info("Executing Reporter Node: Formatting the final report...")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    mitre_kb = state.get("mitre_knowledge_base", {})
    messages = state.get("messages", [])
    initial_clue = state.get("investigation_clue", "未记录初始线索。")
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}

    draft_instruction = (
        next_action.get(
            "instruction",
            "Summarize the investigation findings and generate an attack attribution report.",
        )
        if next_action
        else "Summarize the investigation findings and generate an attack attribution report."
    )

    investigation_notes_list = []
    for msg in messages:
        if msg.type == "ai" and "【调查总结与IOC清单】" in msg.content:
            investigation_notes_list.append(msg.content)

    if investigation_notes_list:
        investigation_notes = "\n\n---\n\n".join(investigation_notes_list)
    else:
        investigation_notes = "No detailed investigation notes found in the history."

    skill_data = load_skill(SKILL_FILE_PATH)
    format_rules = (
        skill_data.get("content")
        or "Please generate a structured and professional forensic report."
    )

    multi_host_instructions = ""
    multi_host_section = ""
    # if is_multi_host:
    #     agent_ip_mapping_str = json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2)
    #     multi_host_instructions = f"""
    #
    # **CRITICAL RULE 6 (MULTI-HOST MAPPING)**: You MUST use the provided Agent ID -> IP mapping to translate any referenced IP addresses into the corresponding Agent IDs in your narrative (e.g., "10.0.0.2 (Agent 002)"). Do NOT invent mappings.
    # """
    #     multi_host_section = (
    #         "### MULTI-HOST MODE\n"
    #         f"Agent ID -> IP Mapping (JSON):\n{agent_ip_mapping_str}\n\n"
    #     )

    reporter_system_prompt = """You are a highly professional Cyber Security Technical Writer.
Your task is to take the raw investigation findings provided by the Forensic Detective and format them into a strict, highly polished Attack Attribution Investigation Report (攻击溯源调查报告).

**CRITICAL RULE 1 (Language)**: You MUST generate the entire final report in Simplified Chinese (简体中文). Please translate the narrative and analysis into natural, professional Chinese cybersecurity terminology. However, you MUST keep exact entities (such as PIDs, IP addresses, exact filenames, ProcessGuids, and specific command-line arguments) in their original format.
**CRITICAL RULE 2 (Factuality)**: You MUST NOT hallucinate, invent, or add any new facts or PIDs. Use ONLY the information provided in the Investigation Notes.
**CRITICAL RULE 3 (Temporal Accuracy)**: You MUST NOT alter, format, or hallucinate any dates or timestamps. Copy the EXACT timestamps provided in the raw findings.
**CRITICAL RULE 4 (Zero-Loss Formatting - CRITICAL)**: You MUST preserve ALL granular technical evidence provided by the Detective. You are STRICTLY FORBIDDEN from summarizing or abstracting low-level details. You MUST seamlessly integrate exact technical parameters (e.g., hex codes, ports, registry paths), complete file paths/names, unredacted command-line arguments, and exact entity IDs (PIDs, IPs, Guids) into your professional narrative. Do NOT use vague generalizations like "accessed a process", "dropped malicious files", or "executed a script".
**CRITICAL RULE 5 (KNOWLEDGE OVERRIDE & AUDIT - ABSOLUTE PRIORITY)**: The Forensic Detective's Investigation Notes represent preliminary analysis. They may occasionally misinterpret native OS behaviors, engine initializations, or benign system noise as malicious tactics. You act as the final QA Auditor. You MUST cross-reference all reported behaviors against the provided `MITRE TACTICS CONTEXT`. If the Detective's qualitative classification conflicts with the specific exclusions, false-positive warnings, or strict definitions outlined in the MITRE KB, the MITRE KB takes absolute precedence. You MUST autonomously correct any misclassifications and apply the MITRE KB's definitive judgment in your final report.

### RESPONSE FORMAT (攻击溯源调查报告)
{format_rules}
{multi_host_instructions}
"""

    try:
        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】\n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No MITRE context available."
        # kb_str = (
        #     json.dumps(mitre_kb, ensure_ascii=False, indent=2)
        #     if mitre_kb
        #     else "No MITRE context available."
        # )
    except Exception as e:
        logger.error("Error formatting vault or KB: %s", e)
        kb_str = str(mitre_kb)

    human_prompt = (
        "### INITIAL TRIGGER (THE STARTING POINT)\n"
        "{initial_clue}\n\n"
        "{multi_host_section}"
        "### CHIEF PLANNER's DRAFT & NARRATIVE FOCUS\n"
        "{draft_instruction}\n\n"
        "### INVESTIGATION NOTES (THE HARD FACTS - DO NOT LOSE ANY DETAILS)\n"
        "{investigation_notes}\n\n"
        "### MITRE TACTICS CONTEXT (For your reference to sound professional)\n"
        "{kb_str}\n\n"
        "Please synthesize the above intelligence and format it exactly according to the requested Report Format."
    )

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", reporter_system_prompt), ("human", human_prompt)]
    )

    logger.info("Generating final report...")
    try:
        reporter_chain = prompt_template | model
        final_report_msg = reporter_chain.invoke(
            {
                "format_rules": format_rules,
                "initial_clue": initial_clue,
                "multi_host_instructions": multi_host_instructions,
                "multi_host_section": multi_host_section,
                "draft_instruction": draft_instruction,
                "investigation_notes": investigation_notes,
                "kb_str": kb_str,
            }
        )

        logger.info("Final report generated successfully.")

        return {
            "final_report": final_report_msg.content,
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=f"报告已生成完毕。\n\n{final_report_msg.content}")],
        }
    except Exception as e:
        logger.error("Error generating final report: %s", e)
        return {
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=f"报告生成失败，发生异常: {e}")],
        }


def user_input_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 6: User Input Node ."""
    logger.info("Executing User Input Node (Suspending...)")

    next_action = state.get("next_action_fromDecisionNode")
    instruction = next_action.get("instruction") if next_action else ""
    clue = state.get("investigation_clue", "")

    if instruction == "ASK_CLUE":
        return {
            "messages": [
                AIMessage(
                    content=f"系统检测到原始日志输入。我为您提取了如下调查线索：\n\n『{clue}』\n\n请问该线索是否符合您的要求？（如果您同意，请回复“是”；如需修改时间范围等信息，请直接指出）"
                )
            ],
            "next_action_fromDecisionNode": None,
        }
    elif instruction == "ASK_CLUE_MODIFIED":
        return {
            "messages": [
                AIMessage(
                    content=f"已根据您的意见修改线索如下：\n\n『{clue}』\n\n请问现在的线索是否符合您的要求？"
                )
            ],
            "next_action_fromDecisionNode": None,
        }
    elif instruction == "ASK_MITRE":
        return {
            "messages": [
                AIMessage(
                    content="调查线索已锁定。为了更精准地识别攻击手法，您是否希望开启 MITRE 专家知识库辅助分析？(输入是或否)"
                )
            ],
            "next_action_fromDecisionNode": None,
        }

    return {"next_action_fromDecisionNode": None}
