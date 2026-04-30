import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from agents.rule_generator.load_skill import get_skill_descriptions, load_skill
from agents.rule_generator.state import RuleGeneratorState
from wazuh_api.indexer_api import search_archived_logs
from wazuh_api.server_api import (
    delete_rule_file,
    get_agents_overview,
    get_config_agentless,
    get_manager_logs,
    get_rule_info,
    get_wazuh_server_api_info,
    restart_manager,
    run_logtest,
    upload_rule_file,
    validate_configuration,
)

logger = logging.getLogger(__name__)


def _normalize_rule_xml(content: str) -> str:
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:xml)?\s*|\s*```$", "", text, flags=re.DOTALL)
    return text.strip()


def _pretty_rule_xml(content: str) -> str:
    normalized = _normalize_rule_xml(content)
    if not normalized:
        return normalized
    try:
        root = ET.fromstring(normalized)
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        return ET.tostring(root, encoding="unicode")
    except Exception:
        return normalized


def _extract_xml_block(text: str) -> str:
    normalized = _normalize_rule_xml(text)
    if not normalized:
        return ""

    xml_match = re.search(r"<group\b[\s\S]*</group>", normalized)
    if xml_match:
        return xml_match.group(0).strip()
    return normalized


def _upload_successful(upload_resp: Any) -> bool:
    if not isinstance(upload_resp, dict):
        return False
    if upload_resp.get("error") not in (None, 0):
        return False
    data = upload_resp.get("data")
    if isinstance(data, dict):
        failed_items = data.get("failed_items")
        if isinstance(failed_items, list) and failed_items:
            return False
        affected_items = data.get("affected_items")
        if isinstance(affected_items, list):
            return len(affected_items) > 0
    return True


def _extract_rule_ids(xml_content: str) -> list[int]:
    if not isinstance(xml_content, str):
        return []
    ids = re.findall(r'<rule\s+id="(\d+)"', xml_content)
    return [int(item) for item in ids]


def _extract_generated_rule_metadata(xml_content: str) -> tuple[int, str]:
    normalized = _normalize_rule_xml(xml_content)
    if not normalized:
        raise ValueError("Generated XML is empty.")

    root = ET.fromstring(normalized)
    first_rule = root.find(".//rule")
    if first_rule is None:
        raise ValueError("Generated XML does not contain any <rule> element.")

    rule_id_raw = first_rule.attrib.get("id")
    if not rule_id_raw or not rule_id_raw.isdigit():
        raise ValueError("Generated XML does not contain a valid numeric rule id.")

    description_node = first_rule.find("description")
    description = ""
    if description_node is not None and description_node.text:
        description = description_node.text.strip()

    return int(rule_id_raw), description


def _extract_referenced_rule_ids(xml_content: str) -> dict[str, list[int]]:
    normalized = _normalize_rule_xml(xml_content)
    if not normalized:
        return {}

    root = ET.fromstring(normalized)
    references: dict[str, list[int]] = {}
    for tag_name in ("if_sid", "if_matched_sid"):
        values: list[int] = []
        for node in root.findall(f".//{tag_name}"):
            text = (node.text or "").strip()
            if not text:
                continue
            values.extend(int(item) for item in re.findall(r"\d+", text))
        if values:
            references[tag_name] = sorted(set(values))
    return references


def _rule_exists(rule_id: int) -> bool:
    rule_info = get_rule_info(rule_id)
    if not isinstance(rule_info, dict):
        return False
    affected_items = rule_info.get("data", {}).get("affected_items", [])
    if not isinstance(affected_items, list):
        return False
    for item in affected_items:
        if isinstance(item, dict) and str(item.get("id")) == str(rule_id):
            return True
    return False


def _extract_manager_log_items(logs_resp: Any) -> list[dict[str, Any]]:
    if not isinstance(logs_resp, dict):
        return []
    data = logs_resp.get("data")
    if isinstance(data, dict):
        items = data.get("affected_items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _format_manager_log_entry(item: dict[str, Any]) -> str:
    timestamp = item.get("timestamp") or item.get("date") or ""
    tag = item.get("tag") or item.get("component") or ""
    level = item.get("level") or ""
    description = item.get("description") or item.get("message") or item.get("log") or ""
    return " | ".join(part for part in [str(timestamp), str(tag), str(level), str(description)] if part).strip()


def _parse_manager_log_timestamp(item: dict[str, Any]) -> datetime | None:
    raw_timestamp = item.get("timestamp") or item.get("date")
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None

    normalized = raw_timestamp.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _get_server_utc_timestamp() -> datetime | None:
    try:
        api_info = get_wazuh_server_api_info()
    except Exception as exc:
        logger.warning(f"Failed to query Wazuh server time: {exc}")
        return None

    if not isinstance(api_info, dict):
        return None

    raw_timestamp = api_info.get("data", {}).get("timestamp")
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None

    normalized = raw_timestamp.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        logger.warning(f"Invalid Wazuh server timestamp format: {raw_timestamp}")
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _find_rule_load_issues(
    filename: str,
    rule_ids: set[int],
    log_items: list[dict[str, Any]],
    not_before: datetime | None = None,
) -> list[str]:
    issues: list[str] = []
    lowered_filename = filename.lower() if filename else ""

    for item in log_items:
        item_timestamp = _parse_manager_log_timestamp(item)
        if not_before and item_timestamp and item_timestamp < not_before:
            continue

        haystacks = [
            str(item.get("description", "")),
            str(item.get("message", "")),
            str(item.get("log", "")),
            str(item.get("tag", "")),
            str(item.get("level", "")),
        ]
        combined = " ".join(haystacks).lower()
        matched_rule_id = any(f"rule '{rid}'" in combined or f"rule {rid}" in combined for rid in rule_ids)
        matched_filename = lowered_filename in combined if lowered_filename else False

        if matched_rule_id or matched_filename:
            issues.append(_format_manager_log_entry(item))

    deduped: list[str] = []
    seen: set[str] = set()
    for issue in issues:
        if issue and issue not in seen:
            seen.add(issue)
            deduped.append(issue)
    return deduped


def _collect_scalar_fields(obj: Any, prefix: str = "", limit: int = 12) -> dict[str, Any]:
    collected: dict[str, Any] = {}

    def walk(node: Any, path: str):
        if len(collected) >= limit:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                walk(value, child_path)
                if len(collected) >= limit:
                    return
            return
        if isinstance(node, list):
            for idx, value in enumerate(node[:3]):
                child_path = f"{path}[{idx}]"
                walk(value, child_path)
                if len(collected) >= limit:
                    return
            return
        if isinstance(node, (str, int, float, bool)) and path:
            collected[path] = node

    walk(obj, prefix)
    return collected


def _ensure_json_compatible_rules(xml_content: str) -> tuple[str, list[int]]:
    normalized = _normalize_rule_xml(xml_content)
    # Intentionally disabled for now.
    # We keep the previous implementation below for possible future reuse, but
    # the current workflow must not auto-clone rules into decoded_as=json
    # variants during verification.
    #
    # if not normalized:
    #     return normalized, []
    # try:
    #     root = ET.fromstring(normalized)
    # except Exception:
    #     return normalized, []
    #
    # existing_ids: set[int] = set()
    # created_json_ids: list[int] = []
    # for rule in root.findall(".//rule"):
    #     rid = rule.attrib.get("id")
    #     if rid and rid.isdigit():
    #         existing_ids.add(int(rid))
    # next_id = (max(existing_ids) + 1) if existing_ids else 110001
    #
    # for parent in root.iter():
    #     children = list(parent)
    #     for child in children:
    #         if child.tag != "rule":
    #             continue
    #         decoded_node = child.find("decoded_as")
    #         if decoded_node is None:
    #             continue
    #         decoded_value = (decoded_node.text or "").strip().lower()
    #         if not decoded_value or decoded_value == "json":
    #             continue
    #
    #         cloned_rule = deepcopy(child)
    #         cloned_decoded_node = cloned_rule.find("decoded_as")
    #         if cloned_decoded_node is not None:
    #             cloned_decoded_node.text = "json"
    #         while next_id in existing_ids:
    #             next_id += 1
    #         cloned_rule.attrib["id"] = str(next_id)
    #         existing_ids.add(next_id)
    #         created_json_ids.append(next_id)
    #         next_id += 1
    #         insert_pos = list(parent).index(child) + 1
    #         parent.insert(insert_pos, cloned_rule)
    #
    # return ET.tostring(root, encoding="unicode"), created_json_ids
    return normalized, []


def _compact_agents_overview(agents_overview: Any) -> dict[str, Any]:
    if not isinstance(agents_overview, dict):
        return {}
    data = agents_overview.get("data", {})
    if not isinstance(data, dict):
        return {}

    nodes = []
    for item in data.get("nodes", []) if isinstance(data.get("nodes"), list) else []:
        if isinstance(item, dict):
            nodes.append(
                {
                    "node_name": item.get("node_name"),
                    "count": item.get("count"),
                }
            )

    groups = []
    for item in data.get("groups", []) if isinstance(data.get("groups"), list) else []:
        if isinstance(item, dict):
            groups.append(
                {
                    "name": item.get("name"),
                    "count": item.get("count"),
                }
            )

    agent_os = []
    for item in data.get("agent_os", []) if isinstance(data.get("agent_os"), list) else []:
        if not isinstance(item, dict):
            continue
        os_info = item.get("os", {})
        if not isinstance(os_info, dict):
            os_info = {}
        agent_os.append(
            {
                "os": {
                    "name": os_info.get("name"),
                    "platform": os_info.get("platform"),
                    "version": os_info.get("version"),
                },
                "count": item.get("count"),
            }
        )

    last_registered_agent = []
    source_last_agents = (
        data.get("last_registered_agent", [])
        if isinstance(data.get("last_registered_agent"), list)
        else []
    )
    for item in source_last_agents[:5]:
        if not isinstance(item, dict):
            continue
        os_info = item.get("os", {})
        if not isinstance(os_info, dict):
            os_info = {}
        last_registered_agent.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "ip": item.get("ip"),
                "status": item.get("status"),
                "group": item.get("group"),
                "node_name": item.get("node_name"),
                "manager": item.get("manager"),
                "version": item.get("version"),
                "lastKeepAlive": item.get("lastKeepAlive"),
                "os": {
                    "name": os_info.get("name"),
                    "platform": os_info.get("platform"),
                    "version": os_info.get("version"),
                },
            }
        )

    return {
        "nodes": nodes,
        "groups": groups,
        "agent_os": agent_os,
        "agent_status": data.get("agent_status"),
        "agent_version": data.get("agent_version"),
        "last_registered_agent": last_registered_agent,
    }


def _compact_agentless_config(agentless_config: Any) -> dict[str, Any]:
    if not isinstance(agentless_config, dict):
        return {}
    data = agentless_config.get("data")
    if isinstance(data, list):
        compact_items = []
        for item in data[:20]:
            if not isinstance(item, dict):
                continue
            compact_items.append(
                {
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "type": item.get("type"),
                    "frequency": item.get("frequency"),
                }
            )
        return {"count": len(data), "items": compact_items}
    if isinstance(data, dict):
        return {
            "enabled": data.get("enabled"),
            "interval": data.get("interval"),
            "hosts_count": len(data.get("hosts", [])) if isinstance(data.get("hosts"), list) else None,
        }
    return {"raw": data}

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


class LogSelection(BaseModel):
    selected_indices: list[int] = Field(
        description="Indices of logs most likely to trigger the generated rule, ordered by confidence."
    )
    reason: str = Field(description="Brief reason for the ranking.")


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


class CleanupTarget(BaseModel):
    rule_id: int | None = Field(
        default=None, description="The rule ID the user wants to delete, if explicitly mentioned."
    )
    filename: str | None = Field(
        default=None,
        description="The exact rule filename the user wants to delete, if explicitly mentioned.",
    )
    use_current_state_rule: bool = Field(
        default=False,
        description="Whether the user is clearly referring to the currently generated/applied rule in the conversation context.",
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
            "agents_overview": _compact_agents_overview(agents_overview),
            "agentless_config": _compact_agentless_config(agentless_config),
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
    user_input_history = (state.get("user_input_history") or []) + [user_input]
    user_input_history = user_input_history[-8:]
    history_text = "\n".join(
        [f"{idx + 1}. {item}" for idx, item in enumerate(user_input_history)]
    )

    generated_rule = state.get("generated_rule")
    logtest_passed = state.get("logtest_passed")

    # Logic for routing
    prompt_context = ""
    if logtest_passed:
        prompt_context = "Rule has been verified and applied. User needs to decide whether to keep it or delete it."
    elif generated_rule:
        prompt_context = "Rule generated but not verified. User needs to decide whether to verify (apply/test) or cancel."
    else:
        return {
            "decision": "extract_requirements",
            "user_input_history": user_input_history,
            # Reset stale state before starting a fresh generation flow.
            "missing_parameters": None,
            "logs_preview": [],
            "raw_logs": [],
            "log_analysis": None,
            "is_feasible": None,
            "infeasibility_reason": None,
            "generated_rule": None,
            "verification_rule_content": None,
            "temp_json_rule_ids": [],
            "rule_id": None,
            "rule_filename": None,
            "validation_error": None,
            "last_validation_error": None,
            "logtest_passed": None,
            "verification_feedback": None,
        }

    parser = PydanticOutputParser(pydantic_object=RouterDecision)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are a router. Determine the user's intent based on the current state.

        Context: {prompt_context}
        Recent User Inputs:
        {history_text}
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
                "history_text": history_text,
                "user_input": user_input,
                "format_instructions": parser.get_format_instructions(),
            }
        )
        return {
            "decision": result.next_step,
            "user_input_history": user_input_history,
        }
    except Exception:
        return {"decision": "unknown", "user_input_history": user_input_history}


def requirement_understanding_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    """Step S2: Requirement Understanding & Scope Definition."""
    logger.info("Executing Requirement Understanding Node")

    messages = state["messages"]
    user_input = messages[-1].content if messages else ""
    user_input_history = (state.get("user_input_history") or [])[-8:]
    user_input_history_text = "\n".join(
        [f"{idx + 1}. {item}" for idx, item in enumerate(user_input_history)]
    )
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

        User Input History (oldest -> latest):
        {user_input_history}

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
        If latest user input is short or ambiguous, use User Input History to infer intent.

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
                "user_input_history": user_input_history_text,
                "existing_reqs": str(existing_reqs),
                "user_input": user_input,
                "format_instructions": parser.get_format_instructions(),
            }
        )

        return {
            "rule_requirements": result.dict(),
            "missing_parameters": result.missing_parameters,
        }
    except Exception as e:
        logger.error(f"Error parsing requirements: {e}")
        return {"missing_parameters": ["Could not parse requirements. Please clarify."]}


def log_retrieval_feasibility_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    logger.info("Executing Log Retrieval & Feasibility Node")
    retrieval_records: list[dict[str, Any]] = []

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
        raw_hits = response.get("hits", {}).get("hits", [])

        def compact_source(source: Any) -> dict[str, Any]:
            if not isinstance(source, dict):
                return {}
            data_obj = source.get("data", {}) if isinstance(source.get("data"), dict) else {}
            decoder_obj = source.get("decoder", {}) if isinstance(source.get("decoder"), dict) else {}
            rule_obj = source.get("rule", {}) if isinstance(source.get("rule"), dict) else {}
            result = {
                "agent": source.get("agent"),
                "manager": source.get("manager"),
                "decoder": source.get("decoder"),
                "rule": source.get("rule"),
                "location": source.get("location"),
                "@timestamp": source.get("@timestamp"),
                "timestamp": source.get("timestamp"),
                "id": source.get("id"),
                "event_summary": {
                    "decoder_name": decoder_obj.get("name"),
                    "rule_id": rule_obj.get("id"),
                    "rule_level": rule_obj.get("level"),
                    "data_top_keys": list(data_obj.keys())[:8] if isinstance(data_obj, dict) else [],
                    "sample_fields": _collect_scalar_fields(data_obj, prefix="data"),
                },
            }
            return {
                key: value
                for key, value in result.items()
                if value not in (None, "", {}, [])
            }

        compact_hits = []
        for hit in raw_hits[:10]:
            compact_hits.append(
                {
                    "_index": hit.get("_index"),
                    "_id": hit.get("_id"),
                    "_source": compact_source(hit.get("_source")),
                }
            )

        total_hits = response.get("hits", {}).get("total", {})
        if isinstance(total_hits, dict):
            total_value = total_hits.get("value", 0)
        elif isinstance(total_hits, int):
            total_value = total_hits
        else:
            total_value = 0

        payload = {
            "meta": {
                "took": response.get("took"),
                "timed_out": response.get("timed_out"),
                "total_hits": total_value,
                "returned_hits": len(compact_hits),
            },
            "hits": compact_hits,
        }
        retrieval_records.append(
            {
                "query": query_body,
                "compact_hits": compact_hits,
                "raw_sources": [
                    {
                        "full_log": hit.get("_source", {}).get("full_log"),
                        "location": hit.get("_source", {}).get("location"),
                        "timestamp": hit.get("_source", {}).get("timestamp")
                        or hit.get("_source", {}).get("@timestamp"),
                        "id": hit.get("_source", {}).get("id"),
                        "agent": hit.get("_source", {}).get("agent"),
                        "decoder": hit.get("_source", {}).get("decoder"),
                        "rule": hit.get("_source", {}).get("rule"),
                    }
                    for hit in raw_hits
                    if isinstance(hit, dict)
                    and isinstance(hit.get("_source"), dict)
                    and isinstance(hit.get("_source", {}).get("full_log"), str)
                    and hit.get("_source", {}).get("full_log", "").strip()
                ],
            }
        )
        return json.dumps(payload, ensure_ascii=False)

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
            {"recursion_limit": 40},
        )

        result_text = ""
        if retrieval_result.get("messages"):
            result_text = retrieval_result["messages"][-1].content or ""
        result_payload = extract_json(result_text)

        attempts = result_payload.get("attempts")
        if not isinstance(attempts, list):
            attempts = []
        if not retrieval_records:
            return {
                "logs_preview": [],
                "raw_logs": [],
                "is_feasible": False,
                "infeasibility_reason": f"No logs found by retrieval agent. Attempts: {json.dumps(attempts, ensure_ascii=False)}",
            }
        last_record = retrieval_records[-1]
        compact_hits = last_record.get("compact_hits", [])
        if not isinstance(compact_hits, list):
            compact_hits = []
        logs = [
            hit.get("_source")
            for hit in compact_hits
            if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
        ]
        raw_logs = last_record.get("raw_sources", [])
        if not isinstance(raw_logs, list):
            raw_logs = []
        if not raw_logs:
            return {
                "logs_preview": [],
                "raw_logs": [],
                "is_feasible": False,
                "infeasibility_reason": f"No usable raw logs found in last retrieval. Attempts: {json.dumps(attempts, ensure_ascii=False)}",
            }

        parser = PydanticOutputParser(pydantic_object=FeasibilityCheck)

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are an expert in Wazuh logs. Analyze the following retrieved logs and rule requirement parameters.
Determine if it is feasible to generate a rule.
Rule Requirement Parameters (structured): {reqs}
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
        logs_sample = raw_logs[:5]
        prompt_logs: list[Any] = []
        for item in logs_sample:
            if not isinstance(item, dict):
                prompt_logs.append(item)
                continue
            normalized_item = dict(item)
            full_log_value = normalized_item.get("full_log")
            if isinstance(full_log_value, str):
                try:
                    normalized_item["full_log_parsed"] = json.loads(full_log_value)
                except Exception:
                    pass
            prompt_logs.append(normalized_item)
        result = chain.invoke(
            {
                "reqs": json.dumps(reqs, ensure_ascii=False, indent=2),
                "logs": json.dumps(prompt_logs, ensure_ascii=False, indent=2),
                "count": len(prompt_logs),
                "format_instructions": parser.get_format_instructions(),
            }
        )

        enriched_analysis = (
            f"{result.log_features}\n\nSearch attempts summary:\n{json.dumps(attempts, ensure_ascii=False)}"
        )
        return {
            "logs_preview": logs,
            "raw_logs": raw_logs,
            "log_analysis": enriched_analysis,
            "is_feasible": result.is_feasible,
            "infeasibility_reason": None if result.is_feasible else result.reason,
        }

    except Exception as e:
        logger.error(f"Error in log retrieval/feasibility: {e}")
        return {
            "logs_preview": [],
            "raw_logs": [],
            "is_feasible": False,
            "infeasibility_reason": f"No logs found due to retrieval error: {str(e)}",
        }


def rule_generation_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    """Step S4: Rule Generation."""
    logger.info("Executing Rule Generation Node")

    skills_to_load = [item["name"] for item in get_skill_descriptions() if item.get("name")]
    skill_names_text = ", ".join(skills_to_load)

    reqs = state.get("rule_requirements", {})
    log_analysis = state.get("log_analysis", "")
    raw_logs = state.get("raw_logs", [])
    validation_error = state.get("validation_error", "")
    user_input_history = (state.get("user_input_history") or [])[-8:]
    user_context = "\n".join(
        [f"{idx + 1}. {item}" for idx, item in enumerate(user_input_history)]
    )

    raw_logs_for_generation = []
    for item in raw_logs:
        if not isinstance(item, dict):
            continue
        full_log = item.get("full_log")
        if isinstance(full_log, str) and full_log.strip():
            raw_logs_for_generation.append(item)
        if len(raw_logs_for_generation) >= 5:
            break

    @tool
    def load_rule_skill(skill_name: str) -> str:
        """Load Wazuh rule syntax skill content by skill name."""
        return load_skill.invoke(skill_name)

    @tool
    def query_rule_by_id(rule_id: int) -> str:
        """Query an existing Wazuh rule by ID before choosing a new rule id or referencing if_sid/if_matched_sid."""
        try:
            rule_info = get_rule_info(rule_id)
        except Exception as exc:
            return f"lookup_failed: rule_id={rule_id}; error={exc}"

        affected_items = []
        if isinstance(rule_info, dict):
            affected_items = rule_info.get("data", {}).get("affected_items", [])
        if not isinstance(affected_items, list) or not affected_items:
            return f"rule_id={rule_id}; exists=false"

        first_item = next((item for item in affected_items if isinstance(item, dict)), None)
        if not first_item:
            return f"rule_id={rule_id}; exists=false"

        return json.dumps(
            {
                "rule_id": rule_id,
                "exists": True,
                "description": first_item.get("description"),
                "level": first_item.get("level"),
                "groups": first_item.get("groups"),
                "filename": first_item.get("filename"),
            },
            ensure_ascii=False,
        )

    try:
        system_prompt = f"""You are a Wazuh Rule Generator Agent.
Generate a valid Wazuh XML rule from requirements and log analysis.
You should use the load_rule_skill tool to fetch needed syntax knowledge.
You should use the query_rule_by_id tool to verify rule IDs before using them.
Available skill names: {skill_names_text}
If previous validation error exists, fix it in the new output.
You must use the provided raw_logs as primary evidence.
The generated rule conditions must match real fields/values that actually exist in raw_logs.
Do not invent nonexistent field paths or values.
Do not use the <decoded_as> element anywhere in the generated rule.
Before choosing a new rule id, query candidate IDs and only use one that does not already exist.
If you choose to use any rule reference such as <if_sid> or <if_matched_sid>, query that rule id first and only use confirmed existing IDs.
Output must be XML only.
Return exactly one valid Wazuh rule XML block rooted at <group>.
Do not wrap the XML in JSON.
Do not add explanations, comments, or markdown fences."""
        generation_agent = create_agent(
            model=model,
            tools=[load_rule_skill, query_rule_by_id],
            system_prompt=system_prompt,
        )
        generation_result = generation_agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "user_context": user_context,
                                "requirements": reqs,
                                "log_analysis": log_analysis,
                                "raw_logs": raw_logs_for_generation,
                                "previous_validation_error": validation_error,
                                "skill_names": skills_to_load,
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            },
            {"recursion_limit": 40},
        )
        result_text = ""
        if generation_result.get("messages"):
            result_text = generation_result["messages"][-1].content or ""
        generated_xml = _extract_xml_block(result_text if isinstance(result_text, str) else "")
        rule_id, rule_description = _extract_generated_rule_metadata(generated_xml)
        if _rule_exists(rule_id):
            raise ValueError(f"Generated rule id {rule_id} already exists in the loaded manager ruleset.")

        referenced_rule_ids = _extract_referenced_rule_ids(generated_xml)
        missing_references: list[str] = []
        for ref_tag, ref_ids in referenced_rule_ids.items():
            for ref_id in ref_ids:
                if not _rule_exists(ref_id):
                    missing_references.append(f"{ref_tag}={ref_id}")
        if missing_references:
            raise ValueError(
                "Generated rule references non-existent rule ids: " + ", ".join(missing_references)
            )

        xml_with_json_compat, temp_json_rule_ids = _ensure_json_compatible_rules(generated_xml)
        pretty_xml = _pretty_rule_xml(generated_xml)
        verification_pretty_xml = _pretty_rule_xml(xml_with_json_compat)
        filename = f"test_rule_{rule_id}.xml"

        return {
            "generated_rule": pretty_xml,
            "verification_rule_content": verification_pretty_xml,
            "temp_json_rule_ids": temp_json_rule_ids,
            "rule_id": rule_id,
            "rule_filename": filename,
            "iteration_count": state.get("iteration_count", 0) + 1,
            "validation_error": None,
            "last_validation_error": validation_error or None,
            "logtest_passed": None,
            "verification_feedback": rule_description or None,
        }
    except Exception as e:
        logger.error(f"Error generating rule: {e}")
        return {
            "generated_rule": None,
            "verification_rule_content": None,
            "temp_json_rule_ids": [],
            "rule_id": None,
            "rule_filename": None,
            "logtest_passed": None,
            "verification_feedback": None,
            "validation_error": f"Error generating rule: {str(e)}",
        }


def rule_verification_node(
    state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel
):
    """Step S5: Rule Application & Verification."""
    logger.info("Executing Rule Verification Node")

    filename = state.get("rule_filename")
    content = state.get("generated_rule")
    verification_content = state.get("verification_rule_content") or content
    rule_id = state.get("rule_id")
    expected_rule_ids = set()
    if isinstance(rule_id, int):
        expected_rule_ids.add(rule_id)
    expected_rule_ids.update(_extract_rule_ids(verification_content or ""))

    if not filename or not content:
        return {"validation_error": "No rule content or filename to verify."}

    try:
        normalized_verification_content = _normalize_rule_xml(verification_content)
        upload_resp = upload_rule_file(filename, normalized_verification_content, overwrite=True)
        if not _upload_successful(upload_resp):
            return {
                "validation_error": f"Upload failed: {json.dumps(upload_resp, ensure_ascii=False)}"
            }

        restart_started_at = _get_server_utc_timestamp()
        restart_resp = restart_manager()
        if restart_resp.get("error") and restart_resp.get("error") != 0:
            return {"validation_error": f"Restart failed: {restart_resp}"}

        val_resp = {}
        validation_exception = ""
        for _ in range(12):
            time.sleep(2)
            try:
                val_resp = validate_configuration()
                if not (val_resp.get("error") and val_resp.get("error") != 0):
                    validation_exception = ""
                    break
            except Exception as e:
                validation_exception = str(e)
                continue
        if validation_exception:
            return {
                "validation_error": f"Configuration validation failed after waiting for manager restart: {validation_exception}"
            }
        if val_resp.get("error") and val_resp.get("error") != 0:
            return {
                "validation_error": f"Configuration validation failed after waiting for manager restart: {val_resp}"
            }

        rule_load_issues: list[str] = []
        rule_loaded = False
        logs_exception = ""
        rule_info_exception = ""
        for _ in range(10):
            time.sleep(1)
            try:
                rule_info = get_rule_info(rule_id) if isinstance(rule_id, int) else {}
                affected_items = (
                    rule_info.get("data", {}).get("affected_items", [])
                    if isinstance(rule_info, dict)
                    else []
                )
                rule_loaded = any(
                    isinstance(item, dict) and int(item.get("id", -1)) == rule_id
                    for item in affected_items
                    if isinstance(item, dict)
                )
                rule_info_exception = ""
            except Exception as e:
                rule_info_exception = str(e)

            try:
                logs_resp = get_manager_logs(limit=100, tag="wazuh-analysisd")
                log_items = _extract_manager_log_items(logs_resp)
                rule_load_issues = _find_rule_load_issues(
                    filename, expected_rule_ids, log_items, not_before=restart_started_at
                )
                logs_exception = ""
            except Exception as e:
                logs_exception = str(e)

            if rule_load_issues or rule_loaded:
                break

        if rule_load_issues:
            concise_issues = rule_load_issues[:5]
            return {
                "validation_error": "Manager loaded the ruleset with warnings/errors related to the uploaded rule file: "
                + " || ".join(concise_issues)
            }

        if isinstance(rule_id, int) and not rule_loaded:
            extra_context = []
            if rule_info_exception:
                extra_context.append(f"rule_info_exception={rule_info_exception}")
            if logs_exception:
                extra_context.append(f"logs_exception={logs_exception}")
            extra_text = f" ({'; '.join(extra_context)})" if extra_context else ""
            return {
                "validation_error": f"Rule {rule_id} was not found in the loaded manager ruleset after restart{extra_text}."
            }

        raw_logs = state.get("raw_logs", [])
        if not raw_logs:
            return {"validation_error": "No raw logs available for logtest."}

        candidate_logs = []
        for item in raw_logs:
            if not isinstance(item, dict):
                continue
            full_log = item.get("full_log")
            if isinstance(full_log, str) and full_log.strip():
                candidate_logs.append(item)
            if len(candidate_logs) >= 5:
                break

        if not candidate_logs:
            return {"validation_error": "No usable raw full_log entries available for logtest."}

        last_output = {}
        attempted = 0
        matched_ids: list[str] = []
        for candidate in candidate_logs:
            log_line = candidate["full_log"]
            attempted += 1
            location = candidate.get("location")
            location_value = location if isinstance(location, str) and location.strip() else None

            try:
                logtest_resp = run_logtest(log_line, location=location_value)
                logger.info(f"Logtest response: {json.dumps(logtest_resp, ensure_ascii=False)}")
            except Exception as e:
                logger.error(f"Logtest API call failed: {e}")
                continue

            # Parse response structure more carefully
            data = logtest_resp.get("data", {})
            # Handle both {"data": {"output": {...}}} and {"data": {...}} structures
            if "output" in data:
                output = data.get("output", {})
            else:
                output = data

            last_output = output if isinstance(output, dict) else {"raw_output": output}

            # Extract matched rule ID
            matched_rule = output.get("rule", {}) if isinstance(output, dict) else {}
            matched_id = matched_rule.get("id")

            if matched_id is not None:
                matched_ids.append(str(matched_id))
                logger.info(f"Matched rule ID: {matched_id}, Expected IDs: {expected_rule_ids}")

            # Convert matched_id to int for comparison
            matched_id_int = None
            try:
                if matched_id is not None:
                    matched_id_int = int(matched_id)
            except (ValueError, TypeError) as e:
                logger.warning(f"Failed to convert matched_id '{matched_id}' to int: {e}")
                matched_id_int = None

            if matched_id_int is not None and matched_id_int in expected_rule_ids:
                return {
                    "logtest_passed": True,
                    "verification_feedback": f"Logtest passed! Matched rule ID: {matched_id}. Expected IDs: {sorted(expected_rule_ids)}. Tried {attempted} sample log(s).",
                }

        failure_details = {
            "attempted_logs": attempted,
            "expected_rule_ids": sorted(expected_rule_ids),
            "matched_ids": matched_ids,
            "last_output": last_output,
        }
        logger.error(f"Logtest verification failed: {json.dumps(failure_details, ensure_ascii=False)}")
        return {
            "logtest_passed": False,
            "validation_error": f"Logtest failed after trying {attempted} sample log(s). Expected rule IDs {sorted(expected_rule_ids)}, matched IDs: {matched_ids}. Last output: {json.dumps(last_output, ensure_ascii=False)}",
        }

    except Exception as e:
        logger.error(f"Error in verification: {e}")
        return {"validation_error": f"Verification process error: {str(e)}"}


def _resolve_rule_filename_from_id(rule_id: int) -> str | None:
    try:
        rule_info = get_rule_info(rule_id)
    except Exception as exc:
        logger.error(f"Failed to resolve filename for rule {rule_id}: {exc}")
        return None

    if not isinstance(rule_info, dict):
        return None
    affected_items = rule_info.get("data", {}).get("affected_items", [])
    if not isinstance(affected_items, list):
        return None

    for item in affected_items:
        if not isinstance(item, dict):
            continue
        filename = item.get("filename")
        if isinstance(filename, str) and filename.strip():
            return filename.strip()
    return None


def cleanup_rule_node(state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel):
    """Cleanup rule if user rejects."""
    logger.info("Executing Cleanup Rule Node")
    messages = state.get("messages", [])
    user_input = messages[-1].content if messages else ""
    current_rule_id = state.get("rule_id")
    current_filename = state.get("rule_filename")

    parser = PydanticOutputParser(pydantic_object=CleanupTarget)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You extract which Wazuh rule file the user wants to delete.

Current conversation state:
- current_rule_id: {current_rule_id}
- current_rule_filename: {current_filename}

Instructions:
- Extract `rule_id` if the user explicitly mentions a rule ID.
- Extract `filename` if the user explicitly mentions a rule filename.
- Set `use_current_state_rule=true` only if the user is clearly referring to the currently generated/applied rule in context, even without repeating the id or filename.
- Do not invent IDs or filenames.

{format_instructions}""",
            ),
            ("human", "{user_input}"),
        ]
    )

    try:
        extraction = (prompt | model | parser).invoke(
            {
                "current_rule_id": current_rule_id,
                "current_filename": current_filename,
                "user_input": user_input,
                "format_instructions": parser.get_format_instructions(),
            }
        )
    except Exception as e:
        logger.error(f"Error extracting cleanup target: {e}")
        return {"verification_feedback": f"Error parsing cleanup target: {e}"}

    filename = extraction.filename.strip() if isinstance(extraction.filename, str) and extraction.filename.strip() else None
    rule_id = extraction.rule_id if isinstance(extraction.rule_id, int) else None

    if not filename and rule_id is not None:
        filename = _resolve_rule_filename_from_id(rule_id)

    if not filename and extraction.use_current_state_rule and isinstance(current_filename, str):
        filename = current_filename.strip() or None
        if rule_id is None and isinstance(current_rule_id, int):
            rule_id = current_rule_id

    if filename:
        try:
            delete_rule_file(filename)
            restart_manager()
            target_text = f"filename={filename}"
            if rule_id is not None:
                target_text += f", rule_id={rule_id}"
            return {"verification_feedback": f"Rule file deleted and manager restarted. ({target_text})"}
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
            return {"verification_feedback": f"Error cleaning up {filename}: {e}"}

    return {
        "verification_feedback": "Could not determine which rule file to delete from the user's input."
    }


def response_node(state: RuleGeneratorState, config: RunnableConfig, model: BaseChatModel):
    """Generate response to the user."""
    logger.info("Executing Response Node")
    missing = state.get("missing_parameters")
    generated_rule = state.get("generated_rule")
    is_feasible = state.get("is_feasible")
    infeasibility_reason = state.get("infeasibility_reason")
    logtest_passed = state.get("logtest_passed")
    validation_error = state.get("validation_error")
    last_validation_error = state.get("last_validation_error")
    verification_feedback = state.get("verification_feedback")
    rule_id = state.get("rule_id")
    logs = state.get("logs_preview", [])

    preview_logs = [item for item in logs[:3] if isinstance(item, dict)]
    display_logs = list(preview_logs)
    log_summary = (
        json.dumps(display_logs, ensure_ascii=False, indent=2)
        if display_logs
        else "无可展示的日志样本。"
    )

    prompt_text = ""

    if missing:
        prompt_text = f"The user requirement is missing the following parameters: {missing}. Ask the user to provide them."
    elif is_feasible is False:
        prompt_text = f"The rule generation is not feasible. Reason: {infeasibility_reason}. Explain this to the user."
    elif verification_feedback and "deleted" in str(verification_feedback):
        prompt_text = "The rule has been deleted as requested. Confirm this to the user."
    elif logtest_passed:
        content = (
            "规则已生成并通过验证。以下是当前规则内容：\n\n"
            f"- 规则ID：{rule_id}\n"
            f"```xml\n{generated_rule}\n```\n\n"
            "本次验证使用的日志样本摘要：\n"
            f"```json\n{log_summary}\n```\n\n"
            "请您确认是否保留并持续应用该规则。\n"
            "如果您希望调整规则内容，也可以直接告诉我修改意见，我会重新生成。"
        )
        return {"messages": [AIMessage(content=content)]}
    elif validation_error:
        if isinstance(validation_error, str) and validation_error.startswith("Error generating rule:"):
            prompt_text = (
                "There was an error while regenerating the rule after a previous validation failure. "
                f"The latest generation attempt failed with: {validation_error}. "
                "Explain that this error belongs to the regeneration attempt, not necessarily to any previously shown rule."
            )
        else:
            prompt_text = (
                f"There was an error during rule verification: {validation_error}. Inform the user."
            )
    elif generated_rule:
        regen_notice = ""
        if isinstance(last_validation_error, str) and last_validation_error.strip():
            regen_notice = (
                "说明：上一轮规则验证失败，已根据失败信息重新生成当前规则。\n"
                f"上一轮失败原因：{last_validation_error}\n\n"
            )
        content = (
            "规则已成功生成。以下是规则内容：\n\n"
            f"{regen_notice}"
            f"- 规则ID：{rule_id}\n"
            f"```xml\n{generated_rule}\n```\n\n"
            "检索到的相关日志样本摘要：\n"
            f"```json\n{log_summary}\n```\n\n"
            "请先审阅这条规则。如果您有修改意见（例如级别、匹配条件、描述、分组等），可直接告诉我，我会按您的意见调整。\n"
            "若规则内容确认无误，我再继续执行验证（会上传规则并重启 Wazuh 管理器）。"
        )
        return {"messages": [AIMessage(content=content)]}
    else:
        prompt_text = "Summarize the current status."

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful assistant. Generate a response to the user based on the current status. Final response must be in Chinese.",
            ),
            ("human", "{prompt_text}"),
        ]
    )

    chain = prompt | model
    result = chain.invoke({"prompt_text": prompt_text})

    return {"messages": [result]}
