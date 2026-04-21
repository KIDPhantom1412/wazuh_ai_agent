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
from .state import ActionCommand, AttributionState
from .utils import load_mitre, load_skill

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


class EvidenceItem(BaseModel):
    indicator_type: str = Field(
        description="The type of the evidence. E.g., 'PID', 'IP_ADDRESS', 'FILE_PATH', 'COMMAND_LINE', 'REGISTRY_KEY', 'PORT'."
    )
    value: str = Field(
        description="The exact value from the log. MUST be unredacted (e.g., exact absolute path, complete command line, exact hex code like '0x1f3fff'). DO NOT truncate."
    )
    timestamp: str = Field(
        description="The exact chronological timestamp. MUST copy-paste the EXACT string directly from the raw JSON log (e.g., '2026-03-10T09:32:30.571Z')."
    )
    description: str = Field(
        description="Technical description of what this artifact did. NEVER generalize into vague actions."
    )
    # mitre_tactic: Optional[str] = Field(
    #     description="The precise technical definition/tactic from the MITRE Expert Knowledge, overriding generic SIEM alerts. Leave null if not applicable."
    # )


class SynthesizedFindings(BaseModel):
    new_evidence: list[EvidenceItem] = Field(
        description="Exhaustive list of all isolated artifacts and raw evidence preserved with ZERO-LOSS."
    )
    summary: str = Field(
        description="A strict chronological timeline and factual summary of the events. Must be affirmatively stated with confident expert tone. Must be in Chinese."
    )


"""
Nodes:
0. Decision_Node
1. Attribution_Planner_Node
2. Log_Retrieval_Node
3. Information_Synthesizer_Node
4. MITRE_Expert_Node - optinal
5. Reporter_Node
6. Evaluator_Node - optional
7. User_Input_Node
"""


def decision_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 0: Decision Node (The Brain for Initialization)."""
    logger.info("Executing Decision Node...")

    is_clue_confirmed = state.get("is_clue_confirmed")
    requires_mitre_kb = state.get("requires_mitre_kb")
    investigation_clue = state.get("investigation_clue")
    pending_type = state.get("pending_question_type")
    messages = state.get("messages", [])

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
                    "investigation_clue": user_text,
                    "is_clue_confirmed": True,
                    "next_action": {"target": "Decision_Node"},
                }
            else:
                return {
                    "investigation_clue": analysis,
                    "pending_question_type": "CLUE",
                    "next_action": {"target": "User_Input_Node", "instruction": "ASK_CLUE"},
                }
        else:
            # 线索已存在，大模型判断用户的回复是同意还是要求修改
            if is_human and pending_type == "CLUE":
                logger.info("Phase 1: Parsing user feedback on clue...")
                system_prompt = """You are an intent parsing and rewriting assistant.
                Current clue: '{clue}'
                User feedback: '{user_text}'
                1. If user agrees/confirms (e.g., '是', 'yes', '确认', 'ok'), output exactly 'AGREE'.
                2. If user wants to modify, rewrite the clue COMPLETELY incorporating their feedback. Output ONLY the new revised clue."""
                prompt = ChatPromptTemplate.from_messages([("system", system_prompt)])
                result = (prompt | model).invoke(
                    {"clue": investigation_clue, "user_text": user_text}
                )
                intent = result.content.strip()

                if intent.upper() == "AGREE":
                    return {
                        "is_clue_confirmed": True,
                        "pending_question_type": None,
                        "next_action": {"target": "Decision_Node"},
                    }
                else:
                    return {
                        "investigation_clue": intent,
                        "next_action": {
                            "target": "User_Input_Node",
                            "instruction": "ASK_CLUE_MODIFIED",
                        },
                    }

    if is_clue_confirmed and requires_mitre_kb is None:
        if is_human and pending_type == "MITRE":
            logger.info("Phase 2: Parsing MITRE response...")
            system_prompt = "Analyze if user agreed (YES) or declined (NO). Chinese '是/开启' = YES, '否/关闭/不用' = NO. Output strictly 'YES' or 'NO'."
            prompt = ChatPromptTemplate.from_messages(
                [("system", system_prompt), ("human", "{user_text}")]
            )
            result = (prompt | model).invoke({"user_text": user_text})
            intent = result.content.strip().upper()

            if "YES" in intent:
                return {
                    "requires_mitre_kb": True,
                    "pending_question_type": None,
                    "messages": [AIMessage(content="已开启 MITRE 专家知识库，正在为您深入调查...")],
                    "next_action": {"target": "Decision_Node"},
                }
            else:
                return {
                    "requires_mitre_kb": False,
                    "pending_question_type": None,
                    "messages": [
                        AIMessage(content="已关闭 MITRE 专家知识库，将仅根据日志事实进行排查...")
                    ],
                    "next_action": {"target": "Decision_Node"},
                }
        else:
            return {
                "pending_question_type": "MITRE",
                "next_action": {"target": "User_Input_Node", "instruction": "ASK_MITRE"},
            }

    logger.info("Initialization complete. Routing to Attribution Planner Node.")
    return {"next_action": {"target": "Attribution_Planner_Node"}}


def attribution_planner_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """
    Node 1: Attribution Planner Node.
    """
    logger.info("Executing Attribution Planner Node")

    use_mitre = state.get("requires_mitre_kb")
    state.get("investigation_clue", "未提供有效初始线索")

    messages = state.get("messages", [])
    vault = state.get("evidence_vault", [])
    mitre_kb = state.get("mitre_knowledge_base", {})

    try:
        vault_str = (
            json.dumps(vault, ensure_ascii=False, indent=2)
            if vault
            else "Vault is currently empty."
        )

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
        vault_str = str(vault)
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

    parser = PydanticOutputParser(pydantic_object=ActionCommand)

    system_prompt = """You are an elite Cybersecurity Chief Attribution Planner.
Your role is to orchestrate a complex attack forensics investigation. You do NOT query databases directly. Instead, you analyze the intelligence gathered so far and delegate specific tasks to specialized subordinate nodes.

## YOUR ARSENAL (TARGET NODES)
- 'Log_Retrieval_Node': Routes to a specialized AI agent equipped with Wazuh API tools.
  - **How to instruct**: Provide clear, natural language instructions detailing *what* you want to find. You MUST explicitly mention *the Agent ID* in your instruction.
  - *Example*: "Investigate PID 6536 on Agent 005 for lateral activities, specifically focusing on File Drops. Apply time range 2026-03-25T10:00:00Z to 2026-03-25T11:00:00Z."

- 'Reporter_Node': Routes to the reporting engine to close the case.
  - **When to use**: Choose this ONLY when you have fully exhausted all leads, built a complete causal tree, and have enough evidence in the vault.
  - **How to instruct**: Provide a brief draft/summary of the attack narrative for the reporter to expand upon.

{mitre_instructions}

### LOG RETRIEVAL NODE INSTRUCTION RULES
When routing to the `Log_Retrieval_Node`, your `instruction` string MUST explicitly declare:
1. **The Investigation Target**: Choose from: numerical `PID`, `FILE_PATH`, `IP_ADDRESS`, `PORT`, `SERVICE_NAME`, or `USER_ACCOUNT`.
2. **The Behavior Type**: Explicitly state WHICH type of behavior you want the node to investigate. Choose ONLY ONE option from the following list—do not select multiple behaviors. The available options are: `Process Creation` (Upward/Downward tracking), `Network Connections`, `DLL/Module Loads`, `Process Injection`, `File Drops`, `Process Tampering`, or `Service Installation`.
3. **Keyword Searches (Last Resort)**: Use generic keyword searches ONLY when an entity lacks the necessary relational identifiers (PID, IP, etc.) to be queried via the primary behaviors.

### YOUR INVESTIGATION STRATEGY (DYNAMIC HUNTING STATE MACHINE)
Execute your investigation as a continuous loop through the following phases. Jump back to earlier phases if new actionable evidence emerges:

#### Phase 1: Lead Triage & Anchoring
Evaluate the initial lead to extract a Process Anchor (PID).
- **Branch A (Non-Process Leads)**: If the lead is a filename, a service name, or an IP address, you are STRICTLY FORBIDDEN from guessing a PID. Your FIRST action MUST be to instruct the Log_Retrieval_Node to pivot on that target to find the process that generated the artifact.
- **Branch B (Process Leads)**: If the lead is a PID, your FIRST action MUST be to instruct the Log_Retrieval_Node to retrieve its exact `Process Creation` log (Upward). If missing, proceed to Phase 2 with the initial PID.

#### Phase 2: Vertical Expansion Loop (The Causal Tree)
With a valid Process Anchor, you MUST build its complete execution lineage. You are REQUIRED to perform BOTH of the following traces for EVERY suspicious process you discover:
- **Descendant Trace (Downward)**: Instruct the Log_Retrieval_Node to find child `Process Creation` logs.
- **Ancestor Trace (Upward)**: Instruct the Log_Retrieval_Node to find parent `Process Creation` logs.

- **EXHAUSTIVE SEARCH & TRANSITION RULE**: You MUST NOT prematurely transition to Phase 3. You may ONLY transition to Phase 3 when the vertical tree is FULLY exhausted. This requires TWO conditions to be met simultaneously:
  1. The Upward trace has reached a dead end (origin parent log is missing OR the ancestor is a confirmed legitimate system broker like explorer.exe or svchost.exe).
  2. The Downward trace confirms that ALL discovered suspicious processes spawned no further unexplored children.

#### Phase 3: The Pivot Protocol (Bridging Lineage Breaks)
When Phase 2 breaks, instruct the Log_Retrieval_Node to perform a Multi-Dimensional Pivot.
- **Logical Breaks**: If you hit a system broker, extract the service/task name and query for `Service Installation`.
- **Physical Breaks/Leaf Nodes**: Query the PID for lateral behaviors like `Network Connections`, `File Drops`, or `DLL/Module Loads` to identify C2 or payloads.
- **Process Injection & Tampering Pivot**: If a benign OS process acts maliciously or exhibits behavior misaligned with its expected function, query it for  `Process Injection` or `Process Tampering` events. Extract the source attacker PID  and return to Phase 2.

#### Phase 4: Contextual Enrichment (Keyword Searches)
- ONLY AFTER Phases 1, 2, and 3 are fully exhausted, instruct the Log_Retrieval_Node to perform Keyword Searches for missing context.
- **THE RE-ENTRY PROTOCOL**: If a keyword search reveals a NEW actionable lead, you MUST immediately loop back to Phase 1/Phase 2.


### CRITICAL RULES
1. **NO DEAD LOOPS**: You MUST read the conversation history. If the Log_Retrieval_Node previously reported "0 results" for a query, DO NOT issue the exact same instruction again. Pivot your strategy.
2. **TIME BOUNDARIES (CRITICAL)**: All backend tools strictly require UTC time. If a time is provided but the timezone is NOT explicitly specified, you MUST default to assuming it is Beijing Time (UTC+8). You MUST manually subtract 8 hours from the provided time to calculate the exact UTC time BEFORE instructing the Log_Retrieval_Node. You MUST pass the complete and exact ISO8601 UTC time boundary in your instructions.

### CURRENT CASE CONTEXT
- **Evidence Vault (Confirmed IOCs/Facts)**:
{vault_str}

- **MITRE Knowledge Base**:
{kb_str}

{format_instructions}
"""

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    chain = prompt | model | parser

    try:
        result = chain.invoke(
            {
                "messages": messages,
                "mitre_instructions": mitre_instructions,
                "vault_str": vault_str,
                "kb_str": kb_str,
                "format_instructions": parser.get_format_instructions(),
            }
        )

        logger.info("Planner decision successful. Target: %s", result.target)

        return {"next_action": {"target": result.target, "instruction": result.instruction}}
    except Exception as e:
        logger.error("Error in attribution planner node: %s", e)
        return {"next_action": None}


def log_retrieval_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 2: Log Retrieval Node"""
    logger.info("Executing Log Retrieval Node")

    next_action = state.get("next_action")
    if not next_action or next_action.get("target") != "Log_Retrieval_Node":
        logger.warning("Invalid route to Log Retrieval Node.")
        return {"current_raw_logs": [], "next_action": None}

    instruction = next_action.get("instruction", "")

    tools = [get_archives_by_keyword, get_archives_by_eventid]

    system_prompt = """You are an elite Data Access & API Agent for the Wazuh Indexer.
Your primary role is to fetch precise security telemetry, logs, and forensic data using the provided tools. You act as the core data engine for other analytical agents and human users.

### TOOL SELECTION LOGIC (STRICT ADHERENCE):
- **Scenario A: Generic Keyword Searches (STRICTLY NON-PROCESS QUERIES)**
  If the instruction explicitly asks to search for a general text string, malicious filename, or IP address (e.g., "Search for mimikatz.exe"), you MUST call `get_archives_by_keyword`.
  *ABSOLUTE BAN (CRITICAL)*: You are STRICTLY FORBIDDEN from executing `get_archives_by_keyword` if the instruction requests tracking a numerical `PID` or specific behavior like "File Drops".

- **Scenario B: Specific Behaviors, Process Trees & Lateral Activity**
  If the instruction asks about process tracking (e.g., "Investigate PID 6536", "Find File Drops"), you MUST call `get_archives_by_eventid`.
  - To find the execution details of a process itself (e.g., finding its creation log), use `query_type="PROCESS_ID"` and `event_ids=["1"]`.
  - To find child processes spawned by a specific parent, use `query_type="PARENT_PROCESS_ID"` and `event_ids=["1"]`.
  - To find lateral activities performed by a process, use `query_type="PROCESS_ID"` with the relevant `event_ids` (e.g., Network=["3"], DLLs=["7"], Injection=["8","10"], File Drops=["11"], Services=["7045"]).
  - **FILE_PATH Retry Rule**: If you execute a `FILE_PATH` query using a full absolute path (e.g., `C:\\Windows\\System32\\malware.exe`) and the tool returns a `search_feedback` error, you MUST automatically extract just the filename (e.g., `malware.exe`) and execute a SECOND tool call using ONLY the filename as the `query_value` before reporting back.

### STRICT TOOL ISOLATION (NO FALLBACKS):
- **NO KEYWORD FALLBACK FOR PIDs**: If the specific process tracking tools return 0 results or a `search_feedback` message for a PID, you MUST simply return that result to the Chief Planner. **DO NOT** attempt to "help" by falling back to `get_archives_by_keyword` to search the PID as a keyword.

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
    next_action = state.get("next_action")
    mitre_kb = state.get("mitre_knowledge_base", {})

    instruction = (
        next_action.get("instruction", "未命名调查任务") if next_action else "未命名调查任务"
    )

    if not raw_logs:
        logger.info("No raw logs provided. Skipping synthesis.")
        return {
            "current_raw_logs": None,
            "next_action": None,
            "messages": [
                AIMessage(
                    content=f"针对指令”{instruction}』“的查询未返回任何日志数据，该方向线索中断。"
                )
            ],
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

### CONTEXT
- **Original Instruction**: {instruction}
- **MITRE Knowledge**:
{kb_str}

{format_instructions}
"""

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "Here are the raw logs to analyze:\n```json\n{logs_str}\n```"),
        ]
    )

    chain = prompt | model | parser

    try:
        logger.info("Synthesizing %d logs...", len(raw_logs))

        result = chain.invoke(
            {
                "instruction": instruction,
                "kb_str": kb_str,
                "logs_str": logs_str,
                "format_instructions": parser.get_format_instructions(),
            }
        )

        if hasattr(result, "new_evidence"):
            new_evidence = [item.model_dump() for item in result.new_evidence]
        else:
            new_evidence = result.get("new_evidence", [])

        summary = (
            result.summary if hasattr(result, "summary") else result.get("summary", "解析完成。")
        )

        logger.info("Synthesis complete. Extracted %d evidence items.", len(new_evidence))

        return {
            "current_raw_logs": None,
            "next_action": None,
            "evidence_vault": new_evidence,
            "messages": [AIMessage(content=summary)],
        }

    except Exception as e:
        logger.error("Error during synthesis: %s", e)
        return {
            "current_raw_logs": None,
            "next_action": None,
            "messages": [
                AIMessage(
                    content=f"[审查官汇报] 针对指令『{instruction}』的日志解析失败。异常信息: {e}"
                )
            ],
        }


def mitre_expert_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 4: MITRE Expert Node ."""
    logger.info("Executing MITRE Expert Node")

    next_action = state.get("next_action")
    instruction = next_action.get("instruction", "")
    technique_ids = re.findall(r"T\d{4}(?:\.\d{3})?", instruction.upper())

    new_knowledge = {}
    existing_kb = state.get("mitre_knowledge_base", {})

    if not technique_ids:
        logger.warning("No MITRE ID found in the instruction: %s", instruction)
    else:
        unique_ids = list(set(technique_ids))

        for tid in unique_ids:
            if tid in existing_kb:
                logger.info("MITRE ID %s is already in the global knowledge base. Skipping.", tid)
                continue

            logger.info("Obtaining knowledge from MITRE KB for: %s", tid)
            try:
                knowledge = load_mitre(MITRE_KB_FILE_PATH, tid)
                if knowledge:
                    new_knowledge[tid] = f"--- External Knowledge FOR {tid} ---\n{knowledge}"
                else:
                    new_knowledge[tid] = (
                        f"No detailed expert guidelines found for {tid}. Please proceed using your general cybersecurity knowledge."
                    )
            except Exception as e:
                logger.error("Error retrieving MITRE KB for %s: %s", tid, e)
                new_knowledge[tid] = f"Failed to retrieve knowledge for {tid} due to system error."

    if new_knowledge:
        logger.info("Successfully retrieved knowledge for %s techniques.", tid)

    return {"mitre_knowledge_base": new_knowledge, "next_action": None}


def reporter_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 5: Reporter Node."""
    logger.info("Executing Reporter Node: Formatting the final report...")

    next_action = state.get("next_action")
    evidence_vault = state.get("evidence_vault", [])
    mitre_kb = state.get("mitre_knowledge_base", {})

    draft_instruction = (
        next_action.get(
            "instruction",
            "Summarize the investigation findings and generate an attack attribution report.",
        )
        if next_action
        else "Summarize the investigation findings and generate an attack attribution report."
    )

    skill_data = load_skill(SKILL_FILE_PATH)
    format_rules = (
        skill_data.get("content")
        or "Please generate a structured and professional forensic report."
    )

    reporter_system_prompt = """You are a highly professional Cyber Security Technical Writer.
Your task is to take the raw investigation findings provided by the Forensic Detective and format them into a strict, highly polished Attack Attribution Investigation Report (攻击溯源调查报告).

**CRITICAL RULE 1 (Language)**: You MUST generate the entire final report in Simplified Chinese (简体中文). Please translate the narrative and analysis into natural, professional Chinese cybersecurity terminology. However, you MUST keep exact entities (such as PIDs, IP addresses, exact filenames, ProcessGuids, and specific command-line arguments) in their original format.
**CRITICAL RULE 2 (Factuality)**: You MUST NOT hallucinate, invent, or add any new facts or PIDs. Use ONLY the information provided in the Evidence Vault.
**CRITICAL RULE 3 (Temporal Accuracy)**: You MUST NOT alter, format, or hallucinate any dates or timestamps. Copy the EXACT timestamps provided in the raw findings.
**CRITICAL RULE 4 (Zero-Loss Formatting - CRITICAL)**: You MUST preserve ALL granular technical evidence provided by the Detective. You are STRICTLY FORBIDDEN from summarizing or abstracting low-level details. You MUST seamlessly integrate exact technical parameters (e.g., hex codes, ports, registry paths), complete file paths/names, unredacted command-line arguments, and exact entity IDs (PIDs, IPs, Guids) into your professional narrative. Do NOT use vague generalizations like "accessed a process", "dropped malicious files", or "executed a script".

### RESPONSE FORMAT (攻击溯源调查报告)
{format_rules}
"""

    try:
        vault_str = (
            json.dumps(evidence_vault, ensure_ascii=False, indent=2)
            if evidence_vault
            else "No concrete evidence extracted."
        )

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
        vault_str = str(evidence_vault)
        kb_str = str(mitre_kb)

    human_prompt = (
        "### CHIEF PLANNER's DRAFT & NARRATIVE FOCUS\n"
        "{draft_instruction}\n\n"
        "### EVIDENCE VAULT (THE HARD FACTS - DO NOT LOSE ANY DETAILS)\n"
        "{vault_str}\n\n"
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
                "draft_instruction": draft_instruction,
                "vault_str": vault_str,
                "kb_str": kb_str,
            }
        )

        logger.info("Final report generated successfully.")

        return {
            "final_report": final_report_msg.content,
            "next_action": None,
            "messages": [AIMessage(content=f"报告已生成完毕。\n\n{final_report_msg.content}")],
        }
    except Exception as e:
        logger.error("Error generating final report: %s", e)
        return {
            "next_action": None,
            "messages": [AIMessage(content=f"报告生成失败，发生异常: {e}")],
        }


def user_input_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 7: User Input Node ."""
    logger.info("Executing User Input Node (Suspending...)")

    next_action = state.get("next_action")
    instruction = next_action.get("instruction") if next_action else ""
    clue = state.get("investigation_clue", "")

    if instruction == "ASK_CLUE":
        return {
            "messages": [
                AIMessage(
                    content=f"系统检测到原始日志输入。我为您提取了如下调查线索：\n\n『{clue}』\n\n请问该线索是否符合您的要求？（如果您同意，请回复“是”；如需修改时间范围等信息，请直接指出）"
                )
            ],
            "next_action": None,
        }
    elif instruction == "ASK_CLUE_MODIFIED":
        return {
            "messages": [
                AIMessage(
                    content=f"已根据您的意见修改线索如下：\n\n『{clue}』\n\n请问现在的线索是否符合您的要求？"
                )
            ],
            "next_action": None,
        }
    elif instruction == "ASK_MITRE":
        return {
            "messages": [
                AIMessage(
                    content="调查线索已锁定。为了更精准地识别攻击手法，您是否希望开启 MITRE 专家知识库辅助分析？(输入是或否)"
                )
            ],
            "next_action": None,
        }

    return {"next_action": None}
