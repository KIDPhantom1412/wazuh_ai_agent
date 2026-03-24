import json
import logging
import re
from typing import Any, Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from agents.rule_generator.load_skill import load_skill
from agents.rule_generator.state import RuleGeneratorState
from wazuh_api.indexer_api import search_archived_logs
from wazuh_api.server_api import (
    delete_rule_file,
    get_agents_overview,
    get_config_agentless,
    get_wazuh_server_api_info,
    restart_manager,
    run_logtest,
    upload_rule_file,
    validate_configuration,
)

logger = logging.getLogger(__name__)

# --- Data Models for Parsing ---


class RuleRequirements(BaseModel):
    agent_id: str | list[str] | None = Field(
        default=None,
        description="Target agent ID(s) (e.g., '001', ['001','004'], or 'all'). Optional if scope is clear or agentless."
    )
    agent_name: str | list[str] | None = Field(
        default=None, description="Target agent name(s) (maps to fixed field agent.name)."
    )
    agent_ip: str | list[str] | None = Field(
        default=None, description="Target agent IP(s) (maps to fixed field agent.ip)."
    )
    scope: str | None = Field(
        default=None,
        description="Description of the target scope (e.g., 'all agents', 'specific agent 001', 'agentless device 192.168.1.1')."
    )
    time_range: str = Field(
        default="now-24h",
        description="Time range for timestamp.gte (e.g., 'now-24h', 'now-3d', 'now-7d' or ISO8601 datetime).",
    )
    filters: dict[str, Any] = Field(
        description="Other filters like source IP, destination IP, port, protocol, etc."
    )
    event_type: str = Field(description="Type of event to detect")
    description: str = Field(description="Description of the rule")
    missing_parameters: list[str] = Field(
        description="List of missing parameters that MUST be clarified before proceeding."
    )


class FeasibilityCheck(BaseModel):
    is_feasible: bool = Field(description="Whether it is feasible to generate the rule")
    reason: str = Field(description="Reason for feasibility or infeasibility")
    log_features: str = Field(description="Extracted log features relevant to the rule")


class GeneratedRule(BaseModel):
    xml_content: str = Field(description="The generated Wazuh rule XML content")
    rule_id: int = Field(description="The ID of the generated rule")
    description: str = Field(description="Description of the rule")


class RouterDecision(BaseModel):
    next_step: Literal[
        "extract_requirements",
        "verify_rule",
        "cancel_verification",
        "keep_rule",
        "delete_rule",
        "unknown",
    ] = Field(
        description="The next step to take based on user input and current state. Use 'extract_requirements' to generate a new rule or modify the current one."
    )


# --- Nodes ---


def environment_perception_node(state: RuleGeneratorState, config: RunnableConfig):
    """Step S1: Environment Perception."""
    logger.info("Executing Environment Perception Node")

    if state.get("environment_info") and state.get("server_timestamp"):
        return {
            "environment_info": state["environment_info"],
            "server_timestamp": state["server_timestamp"],
        }

    try:
        agents_overview = get_agents_overview()
        agentless_config = get_config_agentless()
        server_info = get_wazuh_server_api_info()
        server_timestamp_value = server_info.get("data", {}).get("timestamp", "")
        server_timestamp = (
            server_timestamp_value if isinstance(server_timestamp_value, str) else ""
        )

        env_info = {
            "agents_overview": agents_overview,
            "agentless_config": agentless_config,
            "server_timestamp": server_timestamp,
        }

        formatted_env_info = json.dumps(env_info, indent=2)
        return {"environment_info": formatted_env_info, "server_timestamp": server_timestamp}
    except Exception as e:
        logger.error(f"Error in environment perception: {e}")
        return {
            "environment_info": "Error retrieving environment info.",
            "server_timestamp": "",
        }


def decision_node(state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel):
    """Decide the next step based on user input and state."""
    logger.info("Executing Decision Node")
    messages = state["messages"]
    user_input = messages[-1].content if messages else ""

    generated_rule = state.get("generated_rule")
    logtest_passed = state.get("logtest_passed")

    # Logic for routing
    prompt_context = ""
    if logtest_passed:
        prompt_context = "Rule has been verified and applied. User needs to decide whether to keep it or delete it."
    elif generated_rule:
        prompt_context = "Rule generated but not verified. User needs to decide whether to verify (apply/test) or cancel."
    else:
        return {"decision": "extract_requirements"}

    parser = PydanticOutputParser(pydantic_object=RouterDecision)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are a router. Determine the user's intent based on the current state.

        Context: {prompt_context}
        User Input: {user_input}

        Options:
        - 'verify_rule': User wants to verify/test the generated rule.
        - 'cancel_verification': User wants to cancel the process before verification.
        - 'keep_rule': User wants to keep the applied rule (after verification success).
        - 'delete_rule': User wants to delete/revert the applied rule (after verification success).
        - 'extract_requirements': User wants to generate a new rule, change requirements, or start over.
        - 'unknown': Intent is unclear.

        {format_instructions}
        """,
            ),
            ("human", "{user_input}"),
        ]
    )

    chain = prompt | model | parser
    try:
        result = chain.invoke(
            {
                "prompt_context": prompt_context,
                "user_input": user_input,
                "format_instructions": parser.get_format_instructions(),
            }
        )
        return {"decision": result.next_step}
    except Exception:
        return {"decision": "unknown"}


def requirement_understanding_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    """Step S2: Requirement Understanding & Scope Definition."""
    logger.info("Executing Requirement Understanding Node")

    messages = state["messages"]
    user_input = messages[-1].content if messages else ""
    env_info = state.get("environment_info", "")
    server_timestamp = state.get("server_timestamp", "")

    existing_reqs = state.get("rule_requirements", {})

    parser = PydanticOutputParser(pydantic_object=RuleRequirements)

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are a Wazuh rule generation assistant.
        Your task is to understand the user's rule generation requirement and extract necessary parameters.

        Current Environment Information:
        {env_info}

        Current Wazuh server timestamp (for time understanding):
        {server_timestamp}

        Previous Requirements (if any): {existing_reqs}

        You need to extract:
        1. Target Scope: This could be specific Agent IDs (e.g., '001'), a group of agents, all agents, or specific agentless devices (IPs).
        2. Extract fixed scope fields when user gives them:
           - agent_id -> maps to fixed field agent.id
           - agent_name -> maps to fixed field agent.name
           - agent_ip -> maps to fixed field agent.ip
           - time_range -> maps to fixed field timestamp range
           - if user gives multiple targets, use array format for these fields
           - convert vague time expressions to concrete timestamp.gte expression:
             * 今天/今日 -> now-1d
             * 这几天/最近几天 -> now-3d
             * 最近一周 -> now-7d
             * 最近一个月 -> now-30d
           - if user gives explicit date, output ISO8601 datetime
        3. Specific filters (IP, port, protocol, etc.) not covered by fixed scope fields.
        4. Event Type (e.g., 'ssh_failed', 'file_change')

        If critical information is missing (e.g., the scope is completely unknown), list it in 'missing_parameters'.
        Note: 'agent_id' is optional if the scope refers to agentless devices or is otherwise clear without an ID.
        Ensure 'time_range' is always filled.

        {format_instructions}
        """,
            ),
            ("human", "{user_input}"),
        ]
    )

    chain = prompt | model | parser

    try:
        result = chain.invoke(
            {
                "env_info": env_info,
                "server_timestamp": server_timestamp,
                "existing_reqs": str(existing_reqs),
                "user_input": user_input,
                "format_instructions": parser.get_format_instructions(),
            }
        )

        return {"rule_requirements": result.dict(), "missing_parameters": result.missing_parameters}
    except Exception as e:
        logger.error(f"Error parsing requirements: {e}")
        return {"missing_parameters": ["Could not parse requirements. Please clarify."]}


def log_retrieval_feasibility_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    logger.info("Executing Log Retrieval & Feasibility Node")

    reqs = state.get("rule_requirements", {})
    time_range = reqs.get("time_range", "now-24h")
    base_scope_filter: list[dict[str, Any]] = [
        {"range": {"timestamp": {"gte": time_range, "lte": "now"}}}
    ]

    def append_scope_filter(field_name: str, value: Any):
        if value is None:
            return
        if isinstance(value, list):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            if cleaned:
                base_scope_filter.append({"terms": {field_name: cleaned}})
            return
        value_str = str(value).strip()
        if not value_str:
            return
        if "," in value_str:
            cleaned = [item.strip() for item in value_str.split(",") if item.strip()]
            if cleaned:
                base_scope_filter.append({"terms": {field_name: cleaned}})
            return
        base_scope_filter.append({"term": {field_name: value_str}})

    append_scope_filter("agent.name", reqs.get("agent_name"))
    append_scope_filter("agent.ip", reqs.get("agent_ip"))
    agent_id = reqs.get("agent_id")
    if not (
        isinstance(agent_id, str) and agent_id.strip().lower() == "all"
    ) and not (
        isinstance(agent_id, list) and any(str(item).strip().lower() == "all" for item in agent_id)
    ):
        append_scope_filter("agent.id", agent_id)

    base_scope_query = {
        "query": {"bool": {"filter": base_scope_filter}},
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    @tool
    def query_archived_logs(query_body: dict) -> str:
        """Search archived logs in Wazuh indexer using Elasticsearch query body."""
        response = search_archived_logs(query_body)
        return json.dumps(response, ensure_ascii=False)

    def extract_json(text: str) -> dict[str, Any]:
        text = (text or "").strip()
        if not text:
            return {}
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL)
        try:
            return json.loads(text)
        except Exception:
            match = re.search(r"\{[\s\S]*\}", text)
            if not match:
                return {}
            try:
                return json.loads(match.group(0))
            except Exception:
                return {}

    try:
        retrieval_planner = create_agent(
            model=model,
            tools=[query_archived_logs],
            system_prompt="""You are a Wazuh log retrieval ReAct agent.
You must first query with the provided base_scope_query.
Then infer real field names and value formats from returned logs.
Then query again with a refined query in the same scope.
Finally output strict JSON only:
{
  "attempts": [{"query": {}, "hits": 0}],
  "logs": [],
  "log_analysis": "string",
  "is_feasible": true,
  "infeasibility_reason": "string"
}
Do not output markdown.""",
        )
        retrieval_result = retrieval_planner.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "requirement": reqs,
                                "base_scope_query": base_scope_query,
                            },
                            ensure_ascii=False,
                        ),
                    }
                ]
            },
            {"recursion_limit": 20},
        )

        result_text = ""
        if retrieval_result.get("messages"):
            result_text = retrieval_result["messages"][-1].content or ""
        result_payload = extract_json(result_text)

        logs = result_payload.get("logs")
        if not isinstance(logs, list):
            logs = []

        attempts = result_payload.get("attempts")
        if not isinstance(attempts, list):
            attempts = []

        if not logs:
            scope_response = search_archived_logs(base_scope_query)
            scope_hits = scope_response.get("hits", {}).get("hits", [])
            logs = [item.get("_source", {}) for item in scope_hits]
            attempts.append(
                {
                    "query": base_scope_query,
                    "hits": len(logs),
                    "mode": "fallback_scope_query",
                }
            )

        if not logs:
            return {
                "logs": [],
                "is_feasible": False,
                "infeasibility_reason": f"No logs found by retrieval agent. Attempts: {json.dumps(attempts, ensure_ascii=False)}",
            }

        parser = PydanticOutputParser(pydantic_object=FeasibilityCheck)

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are an expert in Wazuh logs. Analyze the following retrieved logs and the user's requirement.
Determine if it is feasible to generate a rule.
User Requirement: {reqs}
Retrieved Logs (First {count}): {logs}
Analyze the logs for:
1. Field composition
2. Common values
3. Patterns
4. Decoder information
If logs contain relevant events matching the requirement, return feasible=True.
If no relevant logs are found or data is insufficient, return feasible=False and explain why.
{format_instructions}""",
                ),
                ("human", "Analyze feasibility."),
            ]
        )

        chain = prompt | model | parser
        logs_sample = logs[:5]
        result = chain.invoke(
            {
                "reqs": str(reqs),
                "logs": json.dumps(logs_sample, indent=2),
                "count": len(logs_sample),
                "format_instructions": parser.get_format_instructions(),
            }
        )

        enriched_analysis = (
            f"{result.log_features}\n\nSearch attempts summary:\n{json.dumps(attempts, ensure_ascii=False)}"
        )
        return {
            "logs": logs,
            "log_analysis": enriched_analysis,
            "is_feasible": result.is_feasible,
            "infeasibility_reason": result.reason,
        }

    except Exception as e:
        logger.error(f"Error in log retrieval/feasibility: {e}")
        return {
            "logs": [],
            "is_feasible": False,
            "infeasibility_reason": f"No logs found due to retrieval error: {str(e)}",
        }


def rule_generation_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    """Step S4: Rule Generation."""
    logger.info("Executing Rule Generation Node")

    skills_to_load = [
        "rule",
        "group",
        "match",
        "regex",
        "level_attribute",
        "id_attribute",
        "description",
        "decoded_as",
        "field",
        "srcip",
        "dstip",
    ]
    skill_content = ""
    for skill in skills_to_load:
        skill_content += f"\n--- {skill} ---\n{load_skill.invoke(skill)}\n"

    env_info = state.get("environment_info", "")
    reqs = state.get("rule_requirements", {})
    log_analysis = state.get("log_analysis", "")
    validation_error = state.get("validation_error", "")

    parser = PydanticOutputParser(pydantic_object=GeneratedRule)

    system_prompt_template = """You are a Wazuh Rule Generator Agent.

    Your task is to generate a Wazuh XML rule based on the requirements and log analysis.

    Context:
    - Environment: {env_info}
    - Requirements: {reqs}
    - Log Analysis: {log_analysis}

    Rule Syntax Knowledge:
    {skill_content}

    Previous Validation Errors (if any):
    {validation_error}

    Instructions:
    1. Use valid XML format.
    2. Ensure rule ID is unique (use a random ID between 100000-199999 for this temporary rule, or check existing).
       *For this task, generate a random ID in range 110000-119999.*
    3. Include proper description, level, and match/regex.
    4. Group the rule appropriately.
    5. Ensure XML is properly escaped.

    {format_instructions}
    """

    prompt = ChatPromptTemplate.from_messages(
        [("system", system_prompt_template), ("human", "Generate the rule.")]
    )

    chain = prompt | model | parser

    try:
        result = chain.invoke(
            {
                "env_info": env_info,
                "reqs": str(reqs),
                "log_analysis": log_analysis,
                "skill_content": skill_content,
                "validation_error": validation_error,
                "format_instructions": parser.get_format_instructions(),
            }
        )

        filename = f"test_rule_{result.rule_id}.xml"

        return {
            "generated_rule": result.xml_content,
            "rule_id": result.rule_id,
            "rule_filename": filename,
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
    except Exception as e:
        logger.error(f"Error generating rule: {e}")
        return {"validation_error": f"Error generating rule: {str(e)}"}


def rule_verification_node(state: RuleGeneratorState, config: RunnableConfig):
    """Step S5: Rule Application & Verification."""
    logger.info("Executing Rule Verification Node")

    filename = state.get("rule_filename")
    content = state.get("generated_rule")
    rule_id = state.get("rule_id")

    if not filename or not content:
        return {"validation_error": "No rule content or filename to verify."}

    try:
        upload_resp = upload_rule_file(filename, content, overwrite=True)
        if upload_resp.get("error") and upload_resp.get("error") != 0:
            return {"validation_error": f"Upload failed: {upload_resp}"}

        restart_resp = restart_manager()
        if restart_resp.get("error") and restart_resp.get("error") != 0:
            return {"validation_error": f"Restart failed: {restart_resp}"}

        val_resp = validate_configuration()
        if val_resp.get("error") and val_resp.get("error") != 0:
            return {"validation_error": f"Configuration validation failed: {val_resp}"}

        logs = state.get("logs", [])
        if not logs:
            return {"validation_error": "No logs available for logtest."}

        sample_log = logs[0]
        log_line = sample_log.get("full_log") or sample_log.get("message") or json.dumps(sample_log)

        logtest_resp = run_logtest(log_line)

        data = logtest_resp.get("data", {})
        output = data.get("output", data)
        matched_rule = output.get("rule", {})
        matched_id = matched_rule.get("id")

        if str(matched_id) == str(rule_id):
            return {
                "logtest_passed": True,
                "verification_feedback": f"Logtest passed! Matched rule ID: {matched_id}",
            }
        else:
            return {
                "logtest_passed": False,
                "validation_error": f"Logtest failed. Expected rule {rule_id}, but matched {matched_id}. Output: {json.dumps(output)}",
            }

    except Exception as e:
        logger.error(f"Error in verification: {e}")
        return {"validation_error": f"Verification process error: {str(e)}"}


def cleanup_rule_node(state: RuleGeneratorState, config: RunnableConfig):
    """Cleanup rule if user rejects."""
    logger.info("Executing Cleanup Rule Node")
    filename = state.get("rule_filename")
    if filename:
        try:
            delete_rule_file(filename)
            restart_manager()
            return {"verification_feedback": "Rule file deleted and manager restarted."}
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
            return {"verification_feedback": f"Error cleaning up: {e}"}
    return {"verification_feedback": "No rule file to clean up."}


def response_node(state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel):
    """Generate response to the user."""
    logger.info("Executing Response Node")
    missing = state.get("missing_parameters")
    generated_rule = state.get("generated_rule")
    is_feasible = state.get("is_feasible")
    infeasibility_reason = state.get("infeasibility_reason")
    logtest_passed = state.get("logtest_passed")
    validation_error = state.get("validation_error")
    verification_feedback = state.get("verification_feedback")

    prompt_text = ""

    if missing:
        prompt_text = f"The user requirement is missing the following parameters: {missing}. Ask the user to provide them."
    elif is_feasible is False:
        prompt_text = f"The rule generation is not feasible. Reason: {infeasibility_reason}. Explain this to the user."
    elif verification_feedback and "deleted" in str(verification_feedback):
        prompt_text = "The rule has been deleted as requested. Confirm this to the user."
    elif logtest_passed:
        prompt_text = f"The rule has been generated, verified, and passed logtest. Rule content: \n{generated_rule}\n. Ask the user if they want to keep it applied (It is currently applied for testing). If they say no, I will delete it."
    elif validation_error:
        prompt_text = (
            f"There was an error during rule verification: {validation_error}. Inform the user."
        )
    elif generated_rule:
        prompt_text = f"Rule generated successfully: \n{generated_rule}\n. Ask the user if they want to proceed with verification (This involves uploading the rule and restarting the manager)."
    else:
        prompt_text = "Summarize the current status."

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful assistant. Generate a response to the user based on the current status. Final response must be in Chinese.",
            ),
            ("human", prompt_text),
        ]
    )

    chain = prompt | model
    result = chain.invoke({})

    return {"messages": [result]}
