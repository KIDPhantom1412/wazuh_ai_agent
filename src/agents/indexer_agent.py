import datetime
import json
import logging
import re

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from wazuh_api.indexer_api import (
    agent_alerts,
    agent_archives,
    count_agent_alerts,
)

logger = logging.getLogger(__name__)


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

    - **Scenario F: Lateral Activity, Injections & Specific Behaviors (CRITICAL FOR ADVANCED THREATS)**
      If the user asks about what a process *did* laterally—such as network connections, loading DLLs, injecting into other processes, accessing memory, or dropping files—you MUST call: `get_process_activity_logs`.

**2. Strict Tool Isolation (No Fallbacks)**:
    - **Process Queries**: If the instruction asks for a parent process, child processes, or lateral activities for a specific PID or ProcessGuid, you MUST EXCLUSIVELY use `get_parent_process_log`, `get_child_processes_logs`, or `get_process_activity_logs` (Scenarios D, E, and F).
    - **NO KEYWORD FALLBACK**: If the specific process tracking tools return 0 results or an error, you MUST simply return that result to the user. **DO NOT** attempt to "help" by falling back to `get_agent_archives` to search the PID or Guid as a keyword. `get_agent_archives` is strictly for generic text hunting, not process tree resolution.

**3. DATA HANDLING & ROLE BOUNDARIES (CRITICAL)**:
You are exclusively a raw data retrieval pipeline for the Attribution Agent. You MUST adhere strictly to the following constraints:
    - **ZERO HALLUCINATION (ABSOLUTE RULE)**: You are a dumb data pipeline. You MUST NOT generate, simulate, or mock any JSON data. If the tool returns `[]`, `None`, or an error, you MUST EXACTLY output: "No data found for this query." Do not attempt to create an example or guess the log format.
    - **Raw JSON Only**: Output the actual, unmodified JSON data exactly as returned by your tools. This preserves crucial forensic fields (PIDs, command lines, timestamps) preventing data loss for the downstream agent.
    - **No Analysis or Summarization**: DO NOT explain what the logs mean, describe the attack flow, or generate reports (e.g., "Key Findings", "Attack Source"). Leave all attribution and visualization to the other agent.
    - **No Remediation**: Do not suggest response strategies or remediation steps.
    - **CONDITIONAL RESPONSE FORMAT (CRITICAL)**:
      * **SCENARIO 1 (DATA IS FOUND)**: Start with a single sentence, followed IMMEDIATELY by the raw JSON block.
        Example:
        "Here is the lateral activity data for PID 1234 on Agent 005:
        ```json
        [INSERT RAW JSON OUTPUT FROM TOOL HERE]
        ```"
      * **SCENARIO 2 (NO DATA IS FOUND - ESCAPE HATCH)**: IF AND ONLY IF the tool returns an empty list `[]`, `None`, or an error indicating no logs exist, **YOU MUST NOT OUTPUT ANY JSON BLOCK**. You must simply relay the exact failure message in plain text. Do not attempt to create an example or guess the log format to satisfy the downstream agent's request.
        Example:
        "No data found for this query."

"""


@tool
def get_count_agent_alerts(agent_id, starttime, endtime):
    """
    从 Wazuh Indexer 的 wazuh-alerts-* 获取特定 Agent 在指定时间段内的告警日志总数。
    :param agent_id: Agent 的唯一 ID (如 "001")。
    :param starttime: 查询的起始时间。支持相对时间 (如 "now-24h") 或绝对时间 (ISO8601 格式)。
    :param endtime: 查询的结束时间。默认为 "now"。支持相对或绝对时间。
    :return: 匹配条件的告警总数。
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
def get_agent_archives(agent_id: str, keyword: str = "", x_limit: int = 10):
    """
    从 Wazuh Indexer 的 wazuh-archives-*  获取特定 Agent 的日志，支持关键词搜索。
    :param agent_id: Agent 的唯一 ID (如 "001")
    :param keyword: 搜索的关键词 (如 "regsvr32"), 默认为""
    :param x_limit: 返回的日志条数, 默认为 10
    """

    search_results = agent_archives(
        agent_id, keyword=keyword, x_limit=x_limit, payload=None, timeout=300
    )

    hits = search_results.get("hits", {}).get("hits", [])
    archives = [hit["_source"] for hit in hits]

    # 日志简化
    archives = [simplify_log(hit["_source"]) for hit in hits]

    return json.dumps(archives, ensure_ascii=False)


def simplify_log(source):
    """
    用于提取单条日志关键内容，并保持字段路径与原始日志一致。
    仅针对 Windows EventChannel (win) 与 OTRF (ids) 类型进行简化。
    """
    if not isinstance(source, dict):
        return source

    data = source.get("data", {})
    if not isinstance(data, dict):
        return source

    ids = data.get("ids", {})
    win = data.get("win", {})

    # 暂时只处理 ids 和 win 类型的日志；其他类型的日志直接返回
    if not (isinstance(ids, dict) and ids) and not (isinstance(win, dict) and win):
        return source

    # 该函数用于递归地简化嵌套的字典或列表，移除空值、空字典、空列表
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

    # 下面是字段提取逻辑

    # for ts_key in ("@timestamp", "timestamp"):
    #     if source.get(ts_key):
    #         out[ts_key] = source.get(ts_key)

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

    # ids场景
    if isinstance(ids, dict) and ids:
        # ids_keep = [
        #     "UtcTime",
        #     "EventID",
        #     "ProcessId",
        #     "ProcessGuid",
        #     "ProviderGuid",
        #     "ParentProcessId",
        #     "ParentProcessGuid",
        #     "port",
        #     "Image",
        #     "CommandLine",
        #     "ParentImage",
        #     "ParentCommandLine",
        #     "TargetObject",
        #     "User",
        #     "IntegrityLevel",
        #     "DestAddress",
        #     "DestPort",
        #     "SourceAddress",
        #     "SourcePort",
        #     "Protocol",
        #     "Direction",
        #     "Hostname",
        #     # "@timestamp",
        #     "TargetImage",
        #     "TargetProcessId",
        #     "SourceImage",
        #     "SourceProcessId",
        #     "GrantedAccess",
        #     "ImageLoaded",
        #     "Signed",
        #     "TargetFilename",
        # ]
        ids_keep = [
            # 1. 基础进程信息
            "@timestamp",
            "EventID",
            "ProcessId",
            "ProcessGuid",
            "ProviderGuid",
            "ParentProcessId",
            "ParentProcessGuid",
            "User",
            "IntegrityLevel",
            "Hostname",
            # 2. 进程路径兼容 (Sysmon vs WFP)
            "Image",  # Sysmon 专用
            "Application",  # EventID 5156 专用
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            # 3. 网络连接
            "SourceIp",  # Sysmon 3
            "DestinationIp",  # Sysmon 3
            "DestinationPort",  # Sysmon 3
            "SourceAddress",  # EventID 5156
            "DestAddress",  # EventID 5156
            "SourcePort",  # 共用
            "DestPort",  # EventID 5156
            "Protocol",
            "Direction",
            "port",
            # 4. 高级注入与文件行为 (EventID 7, 8, 10, 11)
            "TargetImage",
            "TargetProcessId",
            "TargetObject",
            "SourceImage",
            "SourceProcessId",
            "GrantedAccess",
            "ImageLoaded",
            "TargetFilename",
        ]
        ids_out = {k: ids.get(k) for k in ids_keep if ids.get(k) is not None and ids.get(k) != ""}
        if ids_out:
            out["data"] = {"ids": ids_out}

    # win场景
    elif isinstance(win, dict) and win:
        win_eventdata = (
            win.get("eventdata", {}) if isinstance(win.get("eventdata", {}), dict) else {}
        )
        win_system = win.get("system", {}) if isinstance(win.get("system", {}), dict) else {}

        system_out = {}
        if win_system.get("eventID") is not None and win_system.get("eventID") != "":
            system_out["eventID"] = win_system.get("eventID")

        eventdata_keep = [
            "utcTime",
            "processId",
            "processGuid",
            "parentProcessId",
            "parentProcessGuid",
            "image",
            "commandLine",
            "parentImage",
            "parentCommandLine",
            "targetFilename",
            "targetObject",
            "user",
            "integrityLevel",
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


def search_parent_process(agent_id, pid, timestamp_limit=None):
    """
    查询特定 PID 的进程创建事件
    timestamp_limit: 如果存在，则只查找在此时间之前的创建事件
    """
    # 基础条件
    must_conditions = [{"term": {"agent.id": agent_id}}]
    if timestamp_limit:
        ts_raw = str(timestamp_limit).strip().strip("'\"")
        ts_wazuh = ts_raw.replace("T", " ").replace("Z", "").replace("z", "").strip()
        ts_wazuh = re.sub(r"\s*(?:[+-]\d{2}:?\d{2})\s*$", "", ts_wazuh).strip()

        ts_iso = ts_raw
        if "T" not in ts_iso and " " in ts_iso:
            ts_iso = ts_iso.replace(" ", "T", 1)
        if not re.search(r"(Z|z|[+-]\d{2}:?\d{2})$", ts_iso):
            ts_iso = f"{ts_iso}Z"
        must_conditions.append(
            {
                "bool": {
                    "should": [
                        {"range": {"data.ids.@timestamp": {"lt": ts_iso}}},
                        {"range": {"data.win.eventdata.utcTime": {"lt": ts_wazuh}}},
                        {"range": {"timestamp": {"lt": ts_iso}}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    # Windows 查询条件 (Sysmon EventID 1 或 IDS EventID 1)
    win_conditions = [
        {
            "bool": {
                "should": [
                    {"terms": {"data.win.system.eventID": ["1"]}},
                    {"terms": {"data.ids.EventID": ["1"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    ]
    if "-" in str(pid) and len(str(pid)) > 10:
        win_conditions.append(
            {
                "bool": {
                    "should": [
                        {"term": {"data.win.eventdata.processGuid": str(pid)}},
                        {"term": {"data.ids.ProcessGuid": str(pid)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    else:
        win_conditions.append(
            {
                "bool": {
                    "should": [
                        {"term": {"data.win.eventdata.processId": str(pid)}},
                        {"term": {"data.ids.ProcessId": str(pid)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    # Linux 查询条件 (Auditd)
    # 查找 data.audit.pid 等于 pid 的记录
    linux_conditions = [
        {"exists": {"field": "data.audit.pid"}},
        {"term": {"data.audit.pid": str(pid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}},  # 增加类型过滤，提高准确性
    ]

    # 组合 Windows 或 Linux 条件
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
        "sort": [{"timestamp": {"order": "desc"}}],  # 找离当前时间最近的一次创建
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        # return hits[0]["_source"] if hits else None
        return simplify_log(hits[0]["_source"]) if hits else None
    except Exception as e:
        print(f"Error searching process: {e}")
        return None


def search_child_processes(agent_id, ppid, timestamp_start=None):
    """
    查询特定 PPID (Parent Process ID) 启动的所有子进程
    timestamp_start: 如果存在，则只查找在此时间之后的子进程
    """
    # 基础条件
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # Windows 查询条件 (Sysmon EventID 1 或 IDS EventID 1)
    win_conditions = [
        {
            "bool": {
                "should": [
                    {"terms": {"data.win.system.eventID": ["1"]}},
                    {"terms": {"data.ids.EventID": ["1"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    ]
    if "-" in str(ppid) and len(str(ppid)) > 10:
        win_conditions.append(
            {
                "bool": {
                    "should": [
                        {"term": {"data.win.eventdata.parentProcessGuid": str(ppid)}},
                        {"term": {"data.ids.ParentProcessGuid": str(ppid)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    else:
        win_conditions.append(
            {
                "bool": {
                    "should": [
                        {"term": {"data.win.eventdata.parentProcessId": str(ppid)}},
                        {"term": {"data.ids.ParentProcessId": str(ppid)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    # Linux 查询条件 (Auditd)
    # 查找 data.audit.ppid 等于 ppid 的记录
    linux_conditions = [
        {"exists": {"field": "data.audit.ppid"}},
        {"term": {"data.audit.ppid": str(ppid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}},  # 增加类型过滤
    ]

    # 组合 Windows 或 Linux 条件
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

    # 时间范围限制：子进程的创建时间必须晚于父进程
    if timestamp_start:
        ts_raw = str(timestamp_start).strip().strip("'\"")
        ts_wazuh = ts_raw.replace("T", " ").replace("Z", "").replace("z", "").strip()
        ts_wazuh = re.sub(r"\s*(?:[+-]\d{2}:?\d{2})\s*$", "", ts_wazuh).strip()

        ts_iso = ts_raw
        if "T" not in ts_iso and " " in ts_iso:
            ts_iso = ts_iso.replace(" ", "T", 1)
        if not re.search(r"(Z|z|[+-]\d{2}:?\d{2})$", ts_iso):
            ts_iso = f"{ts_iso}Z"
        must_conditions.append(
            {
                "bool": {
                    "should": [
                        {"range": {"data.ids.@timestamp": {"gte": ts_iso}}},
                        {"range": {"data.win.eventdata.utcTime": {"gte": ts_wazuh}}},
                        {"range": {"timestamp": {"gte": ts_iso}}},
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
        # return [hit["_source"] for hit in hits]
        return [simplify_log(hit["_source"]) for hit in hits]
    except Exception as e:
        print(f"Error searching child processes: {e}")
        return []


@tool
def get_parent_process_log(agent_id: str, pid: str, timestamp_limit: str = None):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 查询给定进程的事件创建日志。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: 进程的 PID(例如: "1234") 或 ProcessGuid(例如: "{70e31e6c-29a2-69ae-9102-000000000800}")
    :param timestamp_limit: (可选) 如果提供，则只查找在此时间之前的创建事件。此参数需严格遵循 ISO8601 格式，例如：2026-03-17T12:00:00Z。
    """
    result = search_parent_process(agent_id, pid, timestamp_limit)

    if result:
        return json.dumps(result, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {"error": f"Could not find a process creation event for PID {pid} on Agent {agent_id}."}
        )


@tool
def get_child_processes_logs(agent_id: str, pid: str, timestamp_start: str = None):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 查询给定进程直接派生（创建）的所有子进程日志。
    不进行递归，只获取直属的子进程创建事件。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: 父进程的 PID(例如: "1234") 或 ProcessGuid(例如: "{70e31e6c...}")
    :param timestamp_start: (可选) 如果提供，则只查找在此时间之后的子进程创建事件。此参数需严格遵循 ISO8601 格式，例如：2026-03-17T12:00:00Z。
    """
    results = search_child_processes(agent_id, pid, timestamp_start)

    if results:
        return json.dumps(results, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {
                "error": f"Could not find any child processes spawned by parent PID {pid} on Agent {agent_id}."
            }
        )


def search_process_activities(
    agent_id: str, pid: str, event_ids: list[str], time_anchor: str = None
):
    """
    查询特定进程的特定横向交互与敏感行为
    """
    # 基础条件
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # 动态传入 event_ids
    if event_ids:
        str_event_ids = [str(eid).strip() for eid in event_ids]
        must_conditions.append(
            {
                "bool": {
                    "should": [
                        {"terms": {"data.ids.EventID": str_event_ids}},
                        {"terms": {"data.win.system.eventID": str_event_ids}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    # 匹配 PID，涵盖源(Source)、目标(Target)和自身(Process)
    pid_str = str(pid).strip()
    if "-" in pid_str and len(pid_str) > 10:
        pid_conditions = [
            {"term": {"data.ids.ProcessGuid": pid_str}},
            {"term": {"data.ids.SourceProcessGuid": pid_str}},
            {"term": {"data.ids.TargetProcessGuid": pid_str}},
            {"term": {"data.win.eventdata.processGuid": pid_str}},
            {"term": {"data.win.eventdata.sourceProcessGuid": pid_str}},
            {"term": {"data.win.eventdata.targetProcessGuid": pid_str}},
        ]
    else:
        pid_conditions = [
            {"term": {"data.ids.ProcessId": pid_str}},
            {"term": {"data.ids.SourceProcessId": pid_str}},
            {"term": {"data.ids.TargetProcessId": pid_str}},
            {"term": {"data.win.eventdata.processId": pid_str}},
            {"term": {"data.win.eventdata.sourceProcessId": pid_str}},
            {"term": {"data.win.eventdata.targetProcessId": pid_str}},
        ]

    must_conditions.append({"bool": {"should": pid_conditions, "minimum_should_match": 1}})

    # 时间范围限制
    if time_anchor:
        try:
            # 清理时间字符串格式
            ts_clean = str(time_anchor).strip().replace("Z", "")
            if "." in ts_clean:
                ts_clean = ts_clean.split(".")[0]  # 丢弃毫秒

            # 解析为 datetime 对象 (兼容带有 'T' 或空格的格式)
            if "T" in ts_clean:
                dt_obj = datetime.datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
            else:
                dt_obj = datetime.datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")

            # 计算时间窗口边界
            time_min = dt_obj - datetime.timedelta(minutes=60)
            time_max = dt_obj + datetime.timedelta(minutes=60)

            # 格式化为 Wazuh UtcTime 格式 (空格分隔)
            wazuh_min = time_min.strftime("%Y-%m-%d %H:%M:%S")
            wazuh_max = time_max.strftime("%Y-%m-%d %H:%M:%S")

            # 格式化为 ISO 格式 (T 分隔，供 timestamp 字段使用)
            iso_min = time_min.strftime("%Y-%m-%dT%H:%M:%S")
            iso_max = time_max.strftime("%Y-%m-%dT%H:%M:%S")

            # 兼容三种时间字段的范围匹配
            must_conditions.append(
                {
                    "bool": {
                        "should": [
                            {
                                "range": {
                                    "data.win.eventdata.utcTime": {
                                        "gte": wazuh_min,
                                        "lte": wazuh_max,
                                    }
                                }
                            },
                            {
                                "range": {
                                    "data.ids.@timestamp": {
                                        "gte": f"{iso_min}Z",
                                        "lte": f"{iso_max}Z",
                                    }
                                }
                            },
                            {"range": {"timestamp": {"gte": f"{iso_min}Z", "lte": f"{iso_max}Z"}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        except Exception as e:
            print(f"Time parsing error for anchor {time_anchor}: {e}")
            pass

    payload = {
        "size": 50,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return "0 logs found in the database."
        return [simplify_log(hit["_source"]) for hit in hits]
    except Exception as e:
        print(f"Error searching lateral activities: {e}")
        return []


@tool
def get_process_activity_logs(
    agent_id: str, pid: str, event_ids: list[str], timestamp_anchor: str = None
):
    """
    获取特定进程的高危横向行为日志。当进程树断裂或需要分析进程具体行为时使用。

    :param agent_id: Agent 的唯一 ID
    :param pid: 必须传入纯数字的 PID (如 "6536")，切勿传入 ProcessGuid。
    :param event_ids: 【必填】一个包含目标 EventID 的字符串列表。你必须根据溯源意图精准选择：
                      - ["3", "5156"]: 查询网络连接 (用于寻找 C2 通信或横向移动)
                      - ["7"]: 查询模块加载/DLL (用于发现 DLL 注入或可疑库加载)
                      - ["8"]: 查询远程线程创建 (CreateRemoteThread，用于发现进程注入的源头)
                      - ["10"]: 查询跨进程访问 (ProcessAccess，用于发现凭据窃取)
                      - ["11"]: 查询文件创建 (用于发现恶意 Payload 落地)
                      一次只选择一类，提高查询精度
    :param timestamp_anchor: (可选) ISO8601 格式的时间锚点。
    """
    if not event_ids:
        return json.dumps({"error": "You MUST provide a list of event_ids to search for."})

    results = search_process_activities(agent_id, pid, event_ids, timestamp_anchor)
    if results:
        return json.dumps(results, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {"error": f"No activity logs found for PID {pid} with event IDs {event_ids}."}
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

    # print("\n--- Q3: 获取普通日志 ---")
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

    # print("\n--- Q4: 获取父进程 ---")
    # messages = [{"role": "user", "content": "获取agent 005 进程为8912的创建日志"}]
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

    # print("\n--- Q5 获取子进程 ---")
    # # messages = [{"role": "user", "content": "获取agent 005 进程为8912的子进程的进程id"}]
    # messages = [{"role": "user", "content": "查找agent 005上ProcessGuid为{70e31e6c-dd80-69b2-f50a-000000000800}的直接子进程。应用timestamp_start '2026-03-12 15:36:32.642'。"}]
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    print("\n--- Q6 查询进程的横向活动 ---")
    # messages = [{"role": "user", "content": "查找agent 005上pid为3732的网络连接活动。应用timestamp_anchor '2020-07-22T04:05:03.447Z'。"}]
    messages = [
        {
            "role": "user",
            "content": "获取进程guid为{b59756a9-baa8-5f17-7807-000000000400}在Agent 005上的进程创建日志。返回完整的原始JSON数据。",
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
