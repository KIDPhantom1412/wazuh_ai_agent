import json
import logging
import re
from enum import Enum

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from wazuh_api.indexer_api import (
    agent_alerts,
    agent_archives,
    count_agent_alerts,
)

logger = logging.getLogger(__name__)


class QueryType(str, Enum):
    PROCESS_ID = "PROCESS_ID"
    FILE_PATH = "FILE_PATH"
    IP_ADDRESS = "IP_ADDRESS"
    PORT = "PORT"
    SERVICE_NAME = "SERVICE_NAME"
    USER_ACCOUNT = "USER_ACCOUNT"


system_prompt = r"""
You are an elite Data Access & API Agent for the Wazuh Indexer.
Your primary role is to fetch precise security telemetry, logs, and forensic data using the provided tools. You act as the core data engine for other analytical agents and human users.

### CORE OPERATIONAL RULES:

**1. Tool Selection Logic (Strict Adherence)**:
    - **Scenario A: Count/Quantity Queries**
      If the user needs to know the **number/count** of alert logs for a specific time period (e.g., "How many alerts?", "Count the warnings"), you MUST call: `get_count_agent_alerts`.

    - **Scenario B: Security Alert Details**
      If the user needs to query **specific alerts or alert logs** (security-related events), you MUST call: `get_agent_alerts`. This tool supports filtering by `ruleId` and time range.

    - **Scenario C: Generic Keyword Searches (STRICTLY NON-PROCESS QUERIES)**
      If the user explicitly asks to search for a general text string, malicious filename, or IP address (e.g., "Search for mimikatz", "Find logs containing 10.10.10.5"), you MUST call: `get_agent_archives`.
      **ABSOLUTE BAN (CRITICAL)**: You are STRICTLY FORBIDDEN from executing `get_agent_archives` if the instruction contains a numerical `PID` , a `ProcessGuid`, or requests a specific `EventID`. If the user asks you to search for a PID or Guid using this function, you MUST REJECT the request and tell them: "Error: Policy prohibits searching PIDs/Guids/EventIDs via keyword archives. Please specify if you need parent, child, or lateral activity logs using the dedicated tools."

    - **Scenario D: Parent Process & Execution Origin**
      If the user specifically needs to search for the **creator/parent** of a single process, or asks questions like "Who created PID X?", "Find the execution details of PID X", you MUST call: `get_parent_process_log`.

    - **Scenario E: Child Processes & Spawned Activity**
      If the user asks for the **child processes** or processes spawned by a specific parent PID (e.g., "What processes were spawned by PID X?"), you MUST call: `get_child_processes_logs`.

    - **Scenario F: Lateral Activity, Injections & Specific Behaviors (CRITICAL FOR ADVANCED Threats)**
      If the user asks about what a process *did* laterally—such as network connections, loading DLLs, injecting into other processes, accessing memory, or dropping files—you MUST call: `get_process_activity_logs`.

**2. Strict Tool Isolation (No Fallbacks)**:
    - **Process Queries**: If the instruction asks for a parent process, child processes, or lateral activities for a specific PID or ProcessGuid, you MUST EXCLUSIVELY use `get_parent_process_log`, `get_child_processes_logs`, or `get_process_activity_logs` (Scenarios D, E, and F).
    - **NO KEYWORD FALLBACK**: If the specific process tracking tools return 0 results or an error, you MUST simply return that result to the user. **DO NOT** attempt to "help" by falling back to `get_agent_archives` to search the PID or Guid as a keyword. `get_agent_archives` is strictly for generic text hunting, not process tree resolution.

**3. DATA HANDLING & ROLE BOUNDARIES (CRITICAL)**:
You are exclusively a raw data retrieval pipeline for the Attribution Agent. You MUST adhere strictly to the following constraints:
    - **ZERO HALLUCINATION (ABSOLUTE RULE)**: You are a dumb data pipeline. You MUST NOT generate, simulate, or mock any JSON data under any circumstances.
    - **No Analysis or Summarization**: DO NOT explain what the logs mean, describe the attack flow, or generate reports (e.g., "Key Findings", "Attack Source"). Leave all attribution and visualization to the other agent.
    - **No Remediation**: Do not suggest response strategies or remediation steps.
    - **CONDITIONAL RESPONSE FORMAT (CRITICAL)**:
      * **SCENARIO 1 (DATA IS FOUND)**: Start with a single sentence, followed IMMEDIATELY by the raw JSON block.
        Example:
        "Here is the lateral activity data for PID 1234 on Agent 005:
        ```json
        [INSERT RAW JSON OUTPUT FROM TOOL HERE]
        ```"
      * **SCENARIO 2 (NO DATA IS FOUND - ESCAPE HATCH)**: IF AND ONLY IF the tool returns a JSON indicating an error or empty results (e.g., `{"error": ...}`), **YOU MUST NOT OUTPUT ANY JSON BLOCK**. You must simply relay the exact failure message in plain text. Do not attempt to create an example or guess the log format to satisfy the downstream agent's request.
        Example:
        "No data found for this query."
"""


@tool
def get_count_agent_alerts(agent_id, starttime, endtime):
    """
    从 Wazuh Indexer 的 wazuh-alerts-* 获取特定 Agent 在指定时间段内的告警日志总数。当用户没有具体说明时区时，默认是北京时间，注意相关字段的时间转换。当用户提问过去/最近一段时间的告警日志总数时，endtime默认为"now"。

    :param agent_id: Agent 的唯一 ID (如 "001")。
    :param starttime: 查询的起始时间。支持相对时间 (如 "now-24h") 或绝对时间 (ISO8601 格式)。
    :param endtime: 查询的结束时间。默认为 "now"。支持相对或绝对时间。
    """
    response_data = count_agent_alerts(agent_id, starttime, endtime)
    count = response_data.get("count", 0)

    result = {
        "agent_id": agent_id,
        "time_range": {"from": starttime, "to": endtime},
        "total_alerts": count,
    }
    return json.dumps(result)


@tool
def get_agent_alerts(agent_id, x_limit, ruleId):
    """
    从 Wazuh Indexer 的 wazuh-alerts-* 获取特定 Agent 的告警日志，支持按 Rule ID 过滤。

    :param agent_id: Agent 的唯一 ID (如 "001")
    :param x_limit: 返回的告警条数
    :param ruleId: 规则 ID (如 5710)，默认为 -1 (不进行规则过滤)
    """
    search_results = agent_alerts(agent_id, x_limit, ruleId)
    hits = search_results.get("hits", {}).get("hits", [])
    alerts = [hit["_source"] for hit in hits]

    return json.dumps(alerts)


@tool
def get_agent_archives(
    agent_id: str,
    keyword: str = "",
    x_limit: int = 10,
    start_time: str = None,
    end_time: str = None,
):
    """
    从 Wazuh Indexer 的 wazuh-archives-* 获取特定 Agent 的原始归档日志，支持关键词搜索和时间过滤。

    :param agent_id: Agent 的唯一 ID (如 "001")
    :param keyword: 搜搜索的关键词 (如 "regsvr32"), 默认为""
    :param x_limit: 返回的日志条数, 默认为 10。
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """

    if start_time:
        start_time = _format_iso8601(start_time)
    if end_time:
        end_time = _format_iso8601(end_time)

    search_results = agent_archives(
        agent_id,
        keyword=keyword,
        x_limit=x_limit,
        payload=None,
        timeout=30,
        start_time=start_time,
        end_time=end_time,
    )

    hits = search_results.get("hits", {}).get("hits", [])
    archives = [simplify_log(hit["_source"]) for hit in hits]

    return json.dumps(archives, ensure_ascii=False)


def simplify_log(source):
    """
    用于提取单条日志关键内容，并保持字段路径与原始日志一致。
    仅针对 Windows EventChannel (win) 类型进行简化。
    """
    if not isinstance(source, dict):
        return source

    data = source.get("data", {})
    if not isinstance(data, dict):
        return source

    win = data.get("win", {})

    if not (isinstance(win, dict) and win):
        return source

    def _prune(obj):
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                pv = _prune(v)
                if pv is None or pv == "":
                    continue
                if isinstance(pv, dict) and not pv:
                    continue
                if isinstance(pv, list) and not pv:
                    continue
                cleaned[k] = pv
            return cleaned
        if isinstance(obj, list):
            cleaned_list = []
            for v in obj:
                pv = _prune(v)
                if pv is None or pv == "":
                    continue
                if isinstance(pv, dict) and not pv:
                    continue
                cleaned_list.append(pv)
            return cleaned_list
        return obj

    out = {}

    if source.get("timestamp"):
        out["timestamp"] = source.get("timestamp")
    elif source.get("@timestamp"):
        out["@timestamp"] = source.get("@timestamp")

    agent = source.get("agent", {})
    if isinstance(agent, dict) and agent.get("id"):
        out["agent"] = {"id": agent.get("id")}

    rule = source.get("rule", {})
    if isinstance(rule, dict) and rule:
        rule_out = {}
        for k in ("id", "level", "description"):
            if rule.get(k) is not None and rule.get(k) != "":
                rule_out[k] = rule.get(k)
        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict) and mitre:
            mitre_out = {}
            if mitre.get("id"):
                mitre_out["id"] = mitre.get("id")
            if mitre.get("tactic"):
                mitre_out["tactic"] = mitre.get("tactic")
            if mitre_out:
                rule_out["mitre"] = mitre_out
        if rule_out:
            out["rule"] = rule_out

    win_eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata", {}), dict) else {}
    win_system = win.get("system", {}) if isinstance(win.get("system", {}), dict) else {}

    system_out = {}
    if win_system.get("eventID") is not None and win_system.get("eventID") != "":
        system_out["eventID"] = win_system.get("eventID")

    eventdata_keep = [
        # --- 1. 基础进程上下文 (Event 1, 3, 7, 11) ---
        "processId",
        "processGuid",
        "image",
        "commandLine",
        "parentProcessId",
        "parentProcessGuid",
        "parentImage",
        "parentCommandLine",
        "originalFileName",
        "integrityLevel",
        # --- 2. 用户与账号身份 (Event 1, 3, 8, 10, 7045) ---
        "user",
        "parentUser",
        "sourceUser",
        "targetUser",
        "accountName",
        # --- 3. 网络通信记录 (Event 3) ---
        "sourceIp",
        "sourcePort",
        "destinationIp",
        "destinationPort",
        "protocol",
        # --- 4. 文件与模块加载 (Event 7, 11) ---
        "targetFilename",  # 文件释放关键字段
        "imageLoaded",  # DLL 劫持/加载关键字段
        "signed",
        # --- 5. 进程注入与内存访问 (Event 8, 10) ---
        "sourceProcessId",
        "sourceImage",
        "targetProcessId",
        "targetImage",
        "sourceProcessGuid",
        "targetProcessGuid",
        "sourceProcessGUID",
        "targetProcessGUID",
        "grantedAccess",
        "startAddress",
        "callTrace",
        # --- 6. 系统服务注册 (Event 7045) ---
        "serviceName",
        "imagePath",
        "serviceType",
        "startType",
    ]

    eventdata_out = {
        k: win_eventdata.get(k)
        for k in eventdata_keep
        if win_eventdata.get(k) is not None and win_eventdata.get(k) != ""
    }

    win_out = {}
    if system_out:
        win_out["system"] = system_out
    if eventdata_out:
        win_out["eventdata"] = eventdata_out
    if win_out:
        out["data"] = {"win": win_out}

    return _prune(out)


def _format_iso8601(ts_raw: str) -> str:
    """
    辅助函数：将时间字符串格式化为标准的 ISO8601 以匹配 Elasticsearch 的 timestamp
    """
    if not ts_raw:
        return None
    ts_iso = str(ts_raw).strip().strip("'\"")
    ts_iso = ts_iso.replace(" ", "T", 1) if "T" not in ts_iso and " " in ts_iso else ts_iso
    if not re.search(r"(Z|z|[+-]\d{2}:?\d{2})$", ts_iso):
        ts_iso = f"{ts_iso}Z"
    return ts_iso


def search_parent_process(agent_id, pid, start_time=None, end_time=None):
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # 统一时间范围查询
    time_range = {}
    if start_time:
        time_range["gte"] = _format_iso8601(start_time)
    if end_time:
        time_range["lte"] = _format_iso8601(end_time)
    if time_range:
        must_conditions.append({"range": {"timestamp": time_range}})

    win_conditions = [{"terms": {"data.win.system.eventID": ["1"]}}]
    if "-" in str(pid) and len(str(pid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.processGuid": str(pid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.processId": str(pid)}})

    linux_conditions = [
        {"exists": {"field": "data.audit.pid"}},
        {"term": {"data.audit.pid": str(pid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}},
    ]

    must_conditions.append(
        {
            "bool": {
                "should": [
                    {"bool": {"must": win_conditions}},
                    {"bool": {"must": linux_conditions}},
                ],
                "minimum_should_match": 1,
            }
        }
    )

    payload = {
        "size": 1,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        return simplify_log(hits[0]["_source"]) if hits else None
    except Exception as e:
        logger.error(f"Error searching parent process: {e}")
        return None


def search_child_processes(agent_id, ppid, start_time=None, end_time=None):
    must_conditions = [{"term": {"agent.id": agent_id}}]

    time_range = {}
    if start_time:
        time_range["gte"] = _format_iso8601(start_time)
    if end_time:
        time_range["lte"] = _format_iso8601(end_time)
    if time_range:
        must_conditions.append({"range": {"timestamp": time_range}})

    win_conditions = [{"terms": {"data.win.system.eventID": ["1"]}}]
    if "-" in str(ppid) and len(str(ppid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessGuid": str(ppid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessId": str(ppid)}})

    linux_conditions = [
        {"exists": {"field": "data.audit.ppid"}},
        {"term": {"data.audit.ppid": str(ppid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}},
    ]

    must_conditions.append(
        {
            "bool": {
                "should": [
                    {"bool": {"must": win_conditions}},
                    {"bool": {"must": linux_conditions}},
                ],
                "minimum_should_match": 1,
            }
        }
    )

    payload = {
        "size": 50,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "asc"}}],
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        return [simplify_log(hit["_source"]) for hit in hits] if hits else []
    except Exception as e:
        logger.error(f"Error searching child processes: {e}")
        return []


def search_process_activities(
    agent_id: str,
    query_type: str,
    query_value: str,
    event_ids: list[str],
    start_time: str = None,
    end_time: str = None,
):
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # 时间过滤
    time_range = {}
    if start_time:
        time_range["gte"] = _format_iso8601(start_time)
    if end_time:
        time_range["lte"] = _format_iso8601(end_time)
    if time_range:
        must_conditions.append({"range": {"timestamp": time_range}})

    # EventID 过滤
    if event_ids:
        str_event_ids = [str(eid).strip() for eid in event_ids]
        must_conditions.append({"terms": {"data.win.system.eventID": str_event_ids}})

    val_str = str(query_value).strip()
    type_conditions = []

    # 3. 动态字段映射逻辑
    if query_type == QueryType.PROCESS_ID:
        type_conditions = [
            {"term": {"data.win.eventdata.processId": val_str}},
            {"term": {"data.win.eventdata.sourceProcessId": val_str}},
            {"term": {"data.win.eventdata.targetProcessId": val_str}},
        ]

    elif query_type == QueryType.FILE_PATH:
        # 基于 query_string 实现模糊匹配
        query_str = f"*{val_str}*"
        type_conditions = [
            {
                "query_string": {
                    "query": query_str,
                    "fields": [
                        "data.win.eventdata.image",
                        "data.win.eventdata.imageLoaded",
                        "data.win.eventdata.sourceImage",
                        "data.win.eventdata.targetImage",
                        "data.win.eventdata.targetFilename",
                        "data.win.eventdata.imagePath",
                        "data.win.eventdata.commandLine",
                    ],
                }
            }
        ]

    elif query_type == QueryType.IP_ADDRESS:
        type_conditions = [
            {"term": {"data.win.eventdata.sourceIp": val_str}},
            {"term": {"data.win.eventdata.destinationIp": val_str}},
        ]

    elif query_type == QueryType.PORT:
        type_conditions = [
            {"term": {"data.win.eventdata.sourcePort": val_str}},
            {"term": {"data.win.eventdata.destinationPort": val_str}},
        ]

    elif query_type == QueryType.SERVICE_NAME:
        # 基于 query_string 实现模糊匹配
        query_str = f"*{val_str}*"
        type_conditions = [
            {"query_string": {"query": query_str, "fields": ["data.win.eventdata.serviceName"]}}
        ]

    elif query_type == QueryType.USER_ACCOUNT:
        # 基于 query_string 实现模糊匹配段
        query_str = f"*{val_str}*"
        type_conditions = [
            {
                "query_string": {
                    "query": query_str,
                    "fields": [
                        "data.win.eventdata.user",
                        "data.win.eventdata.sourceUser",
                        "data.win.eventdata.targetUser",
                        "data.win.eventdata.accountName",
                    ],
                }
            }
        ]

    # 将 OR (should) 逻辑挂载到主查询中
    if type_conditions:
        must_conditions.append({"bool": {"should": type_conditions, "minimum_should_match": 1}})

    payload = {
        "size": 20,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        return [simplify_log(hit["_source"]) for hit in hits] if hits else []
    except Exception as e:
        logger.error(f"Error searching lateral activities: {e}")
        return []


@tool
def get_parent_process_log(agent_id: str, pid: str, start_time: str = None, end_time: str = None):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 查询给定进程的事件创建日志。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: 进程的 PID(例如: "1234") 或 ProcessGuid(例如: "{70e31e6c-29a2-69ae-9102-000000000800}")
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """
    result = search_parent_process(agent_id, pid, start_time, end_time)

    if result:
        return json.dumps(result, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {"error": f"Could not find a process creation event for PID {pid} on Agent {agent_id}."}
        )


@tool
def get_child_processes_logs(agent_id: str, pid: str, start_time: str = None, end_time: str = None):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 查询给定进程直接派生（创建）的所有子进程日志。
    不进行递归，只获取直属的子进程创建事件。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: 父进程的 PID 或 ProcessGuid
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """
    results = search_child_processes(agent_id, pid, start_time, end_time)

    if results:
        return json.dumps(results, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {
                "error": f"Could not find any child processes spawned by parent PID {pid} on Agent {agent_id}."
            }
        )


@tool
def get_process_activity_logs(
    agent_id: str,
    query_type: str,
    query_value: str,
    event_ids: list[str],
    start_time: str = None,
    end_time: str = None,
):
    """
    获取多维度的高危行为日志。当父子进程关联失效，或需要通过特定特征（如 IP、文件名、服务名、账号）横向追踪攻击痕迹时使用。

    :param agent_id: Agent 的唯一 ID
    :param query_type: 【必填】指示查询指标的枚举类型。一次调用只能使用以下一种类型：
        - "PROCESS_ID"   : 按进程 ID 追踪。
        - "FILE_PATH"    : 按文件路径或文件名追踪。
        - "IP_ADDRESS"   : 按源或目的 IP 地址追踪。
        - "PORT"         : 按源或目的网络端口追踪。
        - "SERVICE_NAME" : 按注册的系统服务名称追踪。
        - "USER_ACCOUNT" : 按操作系统用户或服务账号追踪。
    :param query_value: 【必填】与 query_type 对应的具体数值。样例说明：
        - 若为 PROCESS_ID: 传入pid "6536"
        - 若为 FILE_PATH: 传入文件名 "PSEXESVC.EXE", "b.jsp" 或完整路径 "C:\\Windows\\System32\\"
        - 若为 IP_ADDRESS: 传入 "192.168.1.50"
        - 若为 PORT: 传入 "2024"
        - 若为 SERVICE_NAME: 传入"WMI"
        - 若为 USER_ACCOUNT: 传入 "LocalSystem", "Administrator"
    :param event_ids: 【必填】目标 EventID 列表。请严格根据调查意图选择对应的类别：
        - ["1"]         : 进程创建行为 (Process Creation) - 用于检测异常的进程启动、父子关系违规或参数混淆。
        - ["3"]         : 网络连接行为 (Network Connection) - 用于检测 C2 通信、SMB 横向移动或异常端口访问。
        - ["7"]         : 模块加载行为 (Image/DLL Loading) - 用于检测恶意 DLL 注入、劫持或可疑模块调用。
        - ["8", "10"]   : 进程注入与内存访问 (Process Injection & Memory Access) - 用于检测远程线程创建、进程镂空等规避动作。
        - ["11"]        : 文件创建行为 (File Creation) - 用于检测木马落地、WebShell 释放或临时文件生成。
        - ["25"]        : 进程篡改行为 (Process Tampering) - 用于检测进程在内存中的执行镜像被恶意修改或替换的行为。
        - ["7045"]      : 系统服务安装 (Service Installation) - 用于检测权限提升、持久化驻留或通过服务实现的横向移动。
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """
    if not event_ids:
        return json.dumps({"error": "You MUST provide a list of event_ids to search for."})

    results = search_process_activities(
        agent_id, query_type, query_value, event_ids, start_time, end_time
    )
    if results:
        return json.dumps(results, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {
                "error": f"No logs found for {query_type}={query_value} with event IDs {event_ids} within the specified time."
            }
        )


def get_indexer_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[
            get_count_agent_alerts,
            get_agent_alerts,
            get_agent_archives,
            get_parent_process_log,
            get_child_processes_logs,
            get_process_activity_logs,
        ],
        system_prompt=system_prompt,
    )


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )
    indexer_agent = get_indexer_agent(model)

    # print("\n--- Q1: 获取告警数量 ---")
    # for chunk in indexer_agent.stream(
    #     {
    #         "messages": [
    #             {"role": "user", "content": "过去12小时内agent id为001的agent产生多少警告?"}
    #         ]
    #     },
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    # print("\n--- Q2: 获取告警 ---")
    # messages = [{"role": "user", "content": "agent id为004的agent最近3条规则ID为5764的告警?"}]
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    # messages = chunk["messages"]

    # print("\n--- Q3: 关键词搜索日志 ---")
    # messages = [{"role": "user", "content": "获取agent 005 最近一条包含 'pypayload' 的日志"}]
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    # messages = chunk["messages"]

    # print("\n--- Q4: 获取父进程日志 ---")
    # messages = [
    #     {
    #         "role": "user",
    #         "content": "获取agent 005 进程guid为	{70e31e6c-4560-69c3-8c1b-000000000800}的创建日志",
    #     }
    # ]
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    # messages = chunk["messages"]

    # print("\n--- Q5 获取子进程日志 ---")
    # # messages = [{"role": "user", "content": "获取agent 005 进程为13112的子进程的进程id"}]
    # messages = [
    #     {
    #         "role": "user",
    #         "content": "查找agent 005上ProcessGuid为{70e31e6c-4560-69c3-8b1b-000000000800}的直接子进程。",
    #     }
    # ]
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    print("\n--- Q6 查询其他活动日志 ---")
    messages = [
        {
            "role": "user",
            # "content": "调查agent005的网络连接行为，使用query_type='USER_ACCOUNT, query_value='defin',选取EventID 为3。应用时间范围：start_time '2026-03-25T18:41:02+08:00' 和 end_time '2026-03-25T18:45:02+08:00 ",
            # "content": "调查agent005的进程创建日志，使用query_type='FILE_PATH'，query_value='notepad.exe'。应用时间范围：start_time '2026-03-30T09:30:00+08:00' 和 end_time '2026-03-30T09:40:00+08:00'",
            "content": "调查agent005的进程创建日志，使用query_type='FILE_PATH'，query_value='bitsadmin3_flag.ps1'。应用时间范围：start_time '2026-04-13T09:00:00+08:00' 和 end_time '2026-04-13T010:00:00+08:00'",
        }
    ]
    for chunk in indexer_agent.stream(
        {"messages": messages},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
