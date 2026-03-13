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

    - **Scenario D: Process Tree & Execution Lineage**
      If requested to reconstruct an attack chain , trace process ancestors/descendants, or build a **process tree**, you MUST call: `get_process_tree`.
      **Tree Pruning & Formatting Rules**:
      When processing the JSON returned by the tool, you MUST filter and format it before outputting:
      - **Strict Causal Scope**: Focus ONLY on branches related to the current attack.
      - **The Sibling Rule**: If a parent process has multiple children, EXCLUDE irrelevant noise (benign parallel branches or OS initialization). INCLUDE malicious/suspicious siblings spawned at roughly the same time.
      - **Visualization**: Format the final output as a clear ASCII tree. EVERY node MUST explicitly display: `Process Name`, `PID`, `Timestamp`, and the `Full Command Line`.
      [Example Format]
      └── PID 404 (explorer.exe) @ 2026-03-05 09:00:00.000 [Cmd: C:\Windows\explorer.exe]
          └── PID 1234 (cmd.exe) @ 2026-03-05 10:00:00.123 [Cmd: "cmd.exe" /c start "" "C:\Temp\payload.exe"]
              ├── PID 5678 (whoami.exe) @ 2026-03-05 10:00:01.456 [Cmd: whoami /all]
              └── PID 5680 (payload.exe) @ 2026-03-05 10:00:01.500 [Cmd: "C:\Temp\payload.exe" -WindowStyle Hidden -Command "Invoke-WebRequest..."]

**2. Tool Chaining (Crucial for Forensics)**:
    If another agent or user asks you to build a process tree for a specific file or process name (e.g., "mimikatz.exe" or "update.sh") but DOES NOT provide the PID:
    - Step 1: You MUST first use `get_agent_archives` to search for that keyword.
    - Step 2: Extract the exact `ProcessGuid` (preferred for Windows) or `PID` and `Agent ID` from the returned logs.
    - Step 3: ONLY THEN call `get_process_tree` using the extracted PID.

**3. Data Handling & Output Guidelines**:
    - **Absolute Accuracy**: NEVER hallucinate or invent PIDs, Agent IDs, or log entries. If a tool returns no results, explicitly state that no data was found.
    - **Agent-to-Agent Communication**: If your prompt indicates you are gathering evidence for another agent (like the Attribution Agent), ensure your final response includes the raw, unmodified data (especially the full Process Tree JSON, exact PIDs, and Timestamps) so they can perform their analysis without data loss.
    - **Time Formatting**: All timestamps MUST be converted to and displayed in Beijing Time (UTC+8). However, do NOT explicitly append labels like "Beijing Time", "CST", or "UTC+8" to your output. Just present the formatted time directly.

### ROLE BOUNDARIES & RESTRICTIONS (CRITICAL):
You are strictly a data retrieval and process tree visualization engine. You MUST respect the following boundaries:

1. **NO ATTACK ATTRIBUTION OR REPORTING**:
   - You ARE authorized to call tools to construct and output ASCII process trees.
   - **CRITICAL**: You MUST NOT write any analysis sections like "Attack Source Analysis", "Key Findings", "Attack Chain Evolution", or "Incident Summary".
   - **CRITICAL**: DO NOT explain what the process tree means. DO NOT describe the attack flow in text.
   - JUST OUTPUT THE ASCII TREE AND THE RAW LOG DETAILS. NOTHING ELSE.

2. **NO RESPONSE STRATEGIES**: ...

3. **OUTPUT FORMAT**:
   - Only return the tool outputs (e.g., the JSON or the ASCII tree string).
   - If you must speak, keep it extremely brief, e.g., "Here is the process tree data for Agent 005."
   - DO NOT SUMMARIZE the findings. Leave the summarization and attribution to other agent.
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
    :param payload: 查询参数，默认 None
    """

    search_results = agent_archives(agent_id, keyword=keyword, x_limit=x_limit, payload=None)

    hits = search_results.get("hits", {}).get("hits", [])
    archives = [hit["_source"] for hit in hits]

    return json.dumps(archives, ensure_ascii=False)


def search_parent_process(agent_id, pid, timestamp_limit=None):
    """
    查询特定 PID 的进程创建事件
    timestamp_limit: 如果存在，则只查找在此时间之前的创建事件
    """
    # 基础条件
    must_conditions = [{"term": {"agent.id": agent_id}}]
    if timestamp_limit:
        must_conditions.append({"range": {"timestamp": {"lt": timestamp_limit}}})

    # Windows 查询条件 (Sysmon EventID 1)
    win_conditions = [
        {"terms": {"data.win.system.eventID": ["1"]}},
    ]
    if "-" in str(pid) and len(str(pid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.processGuid": str(pid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.processId": str(pid)}})

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
        return hits[0]["_source"] if hits else None
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

    # Windows 查询条件
    win_conditions = [
        {"terms": {"data.win.system.eventID": ["1"]}},
    ]
    if "-" in str(ppid) and len(str(ppid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessGuid": str(ppid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessId": str(ppid)}})

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
        return [hit["_source"] for hit in hits]
    except Exception as e:
        print(f"Error searching child processes: {e}")
        return []


def build_process_node(event):
    """从日志事件中提取进程节点信息"""
    win_data = event.get("data", {}).get("win", {}).get("eventdata")
    audit_data = event.get("data", {}).get("audit")

    if win_data:
        data = win_data
        return {
            "pid": data.get("processGuid") if data.get("processGuid") else data.get("processId"),
            "ppid": (
                data.get("parentProcessGuid")
                if data.get("parentProcessGuid")
                else data.get("parentProcessId")
            ),
            "process_id": data.get("processId"),  # 保留原始 PID 用于显示
            "image": data.get("image"),
            "cmd": data.get("commandLine"),
            "timestamp": event.get("timestamp"),
            "children": [],  # 用于存放子节点
        }
    # 解析 Linux Auditd 数据
    elif audit_data:
        # Auditd 的字段可能因版本或规则不同而略有差异
        # exe 通常是完整路径，command 是命令名
        image = audit_data.get("exe") or audit_data.get("command") or "Unknown"
        # 尝试从 auditd 日志中获取更详细的命令行信息
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


def get_indexer_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[get_count_agent_alerts, get_agent_alerts, get_agent_archives, get_process_tree],
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

    print("\n--- Q1: 获取告警数量 ---")
    for chunk in indexer_agent.stream(
        {
            "messages": [
                {"role": "user", "content": "过去12小时内agent id为001的agent产生多少警告?"}
            ]
        },
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    print("\n--- Q2: 获取告警 ---")
    messages = [{"role": "user", "content": "agent id为004的agent最近3条规则ID为5764的告警?"}]
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

    print("\n--- Q3: 获取普通日志 ---")
    messages = [{"role": "user", "content": "获取agent 005 最近一条包含 'pypayload' 的日志"}]
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
