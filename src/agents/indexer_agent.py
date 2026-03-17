import json
import logging

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

    - **Scenario C: Raw Log/Archive Searches**
      If the user needs to query general **logs or archives** (often for deep investigation or looking for non-alert events), you MUST call: `get_agent_archives`. This tool supports **keyword search**.

    - **Scenario D: Parent Process & Execution Origin**
      If the user specifically needs to search for the **creator/parent** of a single process, or asks questions like "Who created PID X?", "Find the execution details/command line of PID X", you MUST call: `get_parent_process_log`. This is for targeted, single-step upward queries.

    - **Scenario E: Child Processes & Spawned Activity**
      If the user asks for the **child processes** or processes spawned by a specific parent PID (e.g., "What processes were spawned by PID X?", "Find child process logs of PID X"), you MUST call: `get_child_processes_logs`. This is for fetching immediate descendants.

**2. Tool Chaining (Crucial for Forensics)**:
    If another agent or user asks you to investigate a specific file or process name (e.g., "mimikatz.exe" or "update.sh") but DOES NOT provide the PID:
    - Step 1: You MUST first use `get_agent_archives` to search for that keyword.
    - Step 2: Extract the exact `ProcessGuid` (preferred for Windows) or `PID` and `Agent ID` from the returned logs.
    - Step 3: ONLY THEN call `get_parent_process_log` or `get_child_processes_logs` using the extracted PID to find its origin or impact.

**3. Data Handling & Output Guidelines**:
    - **Absolute Accuracy**: NEVER hallucinate or invent PIDs, Agent IDs, or log entries. If a tool returns no results, explicitly state that no data was found.
    - **Agent-to-Agent Communication**: If your prompt indicates you are gathering evidence for another agent (like the Attribution Agent), ensure your final response includes the raw, unmodified data (especially the exact PIDs, command lines, and Timestamps) so they can perform their analysis without data loss.

### ROLE BOUNDARIES & RESTRICTIONS (CRITICAL):
You are strictly a data retrieval engine. You MUST respect the following boundaries:

1. **NO ATTACK ATTRIBUTION OR REPORTING**:
   - **CRITICAL**: You MUST NOT write any analysis sections like "Attack Source Analysis", "Key Findings", "Attack Chain Evolution", or "Incident Summary".
   - **CRITICAL**: DO NOT explain what the logs mean. DO NOT describe the attack flow in text.
   - JUST OUTPUT THE RETRIEVED LOG DETAILS (JSON). NOTHING ELSE.

2. **NO RESPONSE STRATEGIES**: Do not suggest remediation steps.

3. **OUTPUT FORMAT**:
   - Only return the tool outputs (e.g., the JSON data).
   - If you must speak, keep it extremely brief, e.g., "Here is the execution data for PID 1234 on Agent 005."
   - DO NOT SUMMARIZE the findings. Leave the summarization, attribution, and visualization to the other agent.
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

    search_results = agent_archives(agent_id, keyword=keyword, x_limit=x_limit, payload=None)

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

    for ts_key in ("@timestamp", "timestamp"):
        if source.get(ts_key):
            out[ts_key] = source.get(ts_key)

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
        ids_keep = [
            "UtcTime",
            "EventID",
            "ProcessId",
            "ProcessGuid",
            "ProviderGuid",
            "ParentProcessId",
            "ParentProcessGuid",
            "port",
            "Image",
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            "TargetObject",
            "User",
            "IntegrityLevel",
            "@timestamp",
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
        must_conditions.append({"range": {"timestamp": {"lt": timestamp_limit}}})

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
        must_conditions.append({"range": {"timestamp": {"gte": timestamp_start}}})

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


def build_process_node(event):
    """从日志事件中提取进程节点信息"""
    data_root = event.get("data", {})
    win_data = data_root.get("win", {}).get("eventdata")
    ids_data = data_root.get("ids")
    audit_data = data_root.get("audit")

    if ids_data:
        # 优先解析新的 ids 格式
        return {
            "pid": ids_data.get("ProcessGuid") or ids_data.get("ProcessId"),
            "ppid": ids_data.get("ParentProcessGuid") or ids_data.get("ParentProcessId"),
            "process_id": ids_data.get("ProcessId"),
            "image": ids_data.get("Image"),
            "cmd": ids_data.get("CommandLine"),
            "timestamp": ids_data.get("@timestamp") or event.get("timestamp"),
            "port": ids_data.get("port"),
            "children": [],
        }
    elif win_data:
        data = win_data
        return {
            "pid": data.get("processGuid") if data.get("processGuid") else data.get("processId"),
            "ppid": (
                data.get("parentProcessGuid")
                if data.get("parentProcessGuid")
                else data.get("parentProcessId")
            ),
            "process_id": data.get("processId"),
            "image": data.get("image"),
            "cmd": data.get("commandLine"),
            "timestamp": event.get("timestamp"),
            "children": [],
        }
    # 解析 Linux Auditd 数据
    elif audit_data:
        image = audit_data.get("exe") or audit_data.get("command") or "Unknown"
        # 尝试从 auditd 日志中拼接详细的命令行信息
        execve_data = audit_data.get("execve", {})
        if execve_data:
            # 拼接 a0, a1, a2... 参数
            args = []
            i = 0
            while f"a{i}" in execve_data:
                args.append(execve_data[f"a{i}"])
                i += 1
            cmd = " ".join(args)
        else:
            cmd = audit_data.get("command") or "N/A"

        return {
            "pid": audit_data.get("pid"),
            "ppid": audit_data.get("ppid"),
            "process_id": audit_data.get("pid"),
            "image": image,
            "cmd": cmd,
            "timestamp": event.get("timestamp"),
            "children": [],
        }
    return {}


def get_process_descendants(agent_id, ppid, timestamp_start, depth=3):
    """
    向下递归查找子进程树
    """
    if depth <= 0:
        return []

    children_events = search_child_processes(agent_id, ppid, timestamp_start)
    children_nodes = []

    for event in children_events:
        node = build_process_node(event)
        # 递归查找该子进程的子进程
        node["children"] = get_process_descendants(
            agent_id, node["pid"], node["timestamp"], depth - 1
        )
        children_nodes.append(node)

    return children_nodes


def build_process_tree(agent_id, pid, ancestor_depth=5, descendant_depth=3, initial_info=None):
    """
    双向回溯进程树：
    1. 向上找所有祖先 (主干)
    2. 仅对目标进程向下找子孙
    initial_info: (Optional) 如果提供了初始进程信息（如 image, cmd, timestamp），
                  当找不到创建事件时，可以使用这些信息来构建根节点。
    """
    # 1. 向上回溯：找到包括自己在内的祖先链
    ancestor_chain = []
    current_pid = pid  # 这里的 pid 实际上是 ProcessGuid (Windows) 或 PID (Linux)
    current_timestamp = None

    # 获取当前进程的创建事件
    start_event = search_parent_process(agent_id, current_pid)

    target_node = None

    if start_event:
        target_node = build_process_node(start_event)
        current_timestamp = target_node["timestamp"]
        target_node["is_target"] = True  # 标记这是我们的目标线索进程
        ancestor_chain.append(target_node)

        # 向上找父进程
        temp_pid = target_node["ppid"]
        temp_ts = current_timestamp

        for _ in range(ancestor_depth):
            if not temp_pid:
                break
            parent_event = search_parent_process(agent_id, temp_pid, timestamp_limit=temp_ts)
            if not parent_event:
                break

            parent_node = build_process_node(parent_event)
            ancestor_chain.insert(0, parent_node)  # 插到前面

            temp_pid = parent_node["ppid"]
            temp_ts = parent_node["timestamp"]
    else:
        print(
            f"Warning: Could not find creation event for initial PID {pid}. Treating it as root/unknown origin."
        )

        # 尝试使用传入的 initial_info 填充信息
        info = initial_info or {}

        # 创建一个占位节点，尽量填入已知信息
        target_node = {
            "pid": pid,
            "ppid": None,
            "image": info.get("image", "Unknown/Root"),
            "cmd": info.get("cmd", "N/A"),
            "timestamp": info.get("timestamp"),  # 如果有时间戳，可以帮助后续过滤
            "children": [],
            "is_target": True,
        }
        ancestor_chain.append(target_node)

    # 2. 仅对目标进程（ancestor_chain[-1]）向下递归查找子孙
    # 之前是把整棵树都展开了，现在我们回退到只展开 target 的子树
    if target_node:
        target_node["children"] = get_process_descendants(
            agent_id, target_node["pid"], target_node["timestamp"], descendant_depth
        )

    # 返回祖先链，其中最后一个元素（target_node）挂载了子树
    return ancestor_chain


@tool
def get_process_tree(
    agent_id: str, pid: str, image: str = "Unknown", cmd: str = "N/A", timestamp: str = None
):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 重建进程执行树。
    用于追踪是谁启动了某个进程，并获取完整的父子进程执行链。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: ProcessGuid (例如: "{70e31e6c-29a2-69ae-9102-000000000800}") 或进程 PID (例如: "1234")
    :param image: (可选) 进程镜像名称或文件路径
    :param cmd: (可选) 进程执行时的命令行参数
    :param timestamp: (可选) 该进程日志记录的时间戳
    """
    initial_info = {"image": image, "cmd": cmd, "timestamp": timestamp}

    tree = build_process_tree(agent_id, pid, initial_info=initial_info)

    if not tree:
        return (
            "Could not find process tree for this PID. Please ensure agent_id and pid are correct."
        )
    return json.dumps(tree, ensure_ascii=False, indent=2)


@tool
def get_parent_process_log(agent_id: str, pid: str, timestamp_limit: str = None):
    """
    基于 ProcessGuid (Windows 优先) 或 PID (Linux/Windows 备用) 查询给定进程的事件创建日志。

    :param agent_id: Agent 的唯一 ID (例如: "005")
    :param pid: 进程的 PID(例如: "1234") 或 ProcessGuid(例如: "{70e31e6c-29a2-69ae-9102-000000000800}")
    :param timestamp_limit: (可选) 如果提供，则只查找在此时间之前的创建事件。支持 ISO8601 格式。
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
    :param timestamp_start: (可选) 如果提供，则只查找在此时间之后的子进程创建事件。支持 ISO8601 格式。
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


def get_indexer_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[
            get_count_agent_alerts,
            get_agent_alerts,
            get_agent_archives,
            get_parent_process_log,
            get_child_processes_logs,
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

    print("\n--- Q4: 获取父进程 ---")
    messages = [{"role": "user", "content": "获取agent 005 进程为8912的创建日志"}]
    for chunk in indexer_agent.stream(
        {"messages": messages},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    messages = chunk["messages"]

    print("\n--- Q5 获取子进程 ---")
    messages = [{"role": "user", "content": "获取agent 005 进程为8912的子进程的进程id"}]
    for chunk in indexer_agent.stream(
        {"messages": messages},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    messages = chunk["messages"]
