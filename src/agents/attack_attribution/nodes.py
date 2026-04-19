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
1. Attribution_Planner_Node
2. Log_Retrieval_Node
3. Information_Synthesizer_Node
4. MITRE_Expert_Node - optinal
5. Reporter_Node
6. Evaluator_Node - optional
7. User_Input_Node
"""


def attribution_planner_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """
    Node 1: Attribution Planner Node.
    """
    logger.info("Executing Attribution Planner Node")

    use_mitre = state.get("requires_mitre_kb")
    if use_mitre is None:
        logger.info("Ask the user whether to enable the MITRE knowledge base....")
        return {
            "next_action": {
                "target": "User_Input_Node",
                "instruction": "攻击溯源调查已启动。您是否希望开启 MITRE 专家知识库辅助分析？",
            }
        }

    messages = state.get("messages", [])
    vault = state.get("evidence_vault", [])
    mitre_kb = state.get("mitre_knowledge_base", {})

    try:
        vault_str = (
            json.dumps(vault, ensure_ascii=False, indent=2)
            if vault
            else "Vault is currently empty."
        )
        kb_str = (
            json.dumps(mitre_kb, ensure_ascii=False, indent=2)
            if mitre_kb
            else "No external knowledge retrieved yet."
        )
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

- 'User_Input_Node': Routes to the human operator.
  - **When to use**: Use this ONLY if you need to ask the human user a clarifying question to proceed.

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
        kb_str = (
            json.dumps(mitre_kb, ensure_ascii=False, indent=2)
            if mitre_kb
            else "No MITRE context available."
        )
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
        kb_str = (
            json.dumps(mitre_kb, ensure_ascii=False, indent=2)
            if mitre_kb
            else "No MITRE context available."
        )
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
    """Node 7: User Input Node."""
    logger.info("Executing User Input Node")

    requires_mitre_kb = state.get("requires_mitre_kb")
    has_asked_mitre = state.get("has_asked_mitre", False)
    messages = state.get("messages", [])

    last_message = messages[-1] if messages else None
    is_human = last_message.type == "human" if last_message else False
    user_text = last_message.content if is_human else ""

    # 情况 1：requires_mitre_kb 为 None
    if requires_mitre_kb is None:

        # 1.1 如果已经提问过，且最新消息是用户发的，说明用户正在回答，调用大模型解析意图
        if has_asked_mitre and is_human:
            logger.info("Parsing user intent using LLM...")

            system_prompt = (
                "You are an intent parsing assistant. The user was asked if they want to enable the MITRE ATT&CK knowledge base. "
                "Analyze the user's input and determine if they agreed (YES) or declined (NO). "
                "CRITICAL RULE: Even if the user replies in Chinese (e.g., '是', '好的', '开启', 'yes', 'y'), you MUST output exactly the English word 'YES'. "
                "If they decline (e.g., '否', '不要', '关闭', 'no', 'n'), output exactly 'NO'. "
                "Output strictly 'YES' or 'NO' with no other text."
            )

            prompt = ChatPromptTemplate.from_messages(
                [("system", system_prompt), ("human", "{user_text}")]
            )

            try:
                result = (prompt | model).invoke({"user_text": user_text})
                intent = result.content.strip().upper()

                if "YES" in intent:
                    logger.info("Parsed Intent: YES (from LLM)")
                    return {
                        "requires_mitre_kb": True,
                        "next_action": None,
                        "messages": [
                            AIMessage(content="已为您开启 MITRE 专家知识库，正在为您深入调查...")
                        ],
                    }
                else:
                    logger.info("Parsed Intent: NO (from LLM)")
                    return {
                        "requires_mitre_kb": False,
                        "next_action": None,
                        "messages": [
                            AIMessage(
                                content="已关闭 MITRE 专家知识库，将仅根据日志事实进行排查..."
                            )
                        ],
                    }
            except Exception as e:
                logger.error("Error parsing user intent: %s", e)
                return {"next_action": None}

        # 1.2 如果尚未提问，生成询问提示词，并更新提问状态
        else:
            logger.info("Prompting user for MITRE KB usage.")
            return {
                "has_asked_mitre": True,
                "messages": [
                    AIMessage(
                        content="调查已启动。为了更精准地识别攻击手法，您是否希望开启 MITRE 专家知识库辅助分析？(输入 yes 或 no)"
                    )
                ],
            }

    # 情况 2：其他情况直接 return
    logger.info("No user input required at this stage. Returning control.")

    # 清空 next_action，防止死循环，把图的流转权交回给大脑
    return {"next_action": None}
