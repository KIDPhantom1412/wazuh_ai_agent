import json

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from wazuh_api.indexer_api import agent_archives

system_prompt = r"""
You are an expert AI security agent interacting with the Wazuh indexer API. Your primary task is to assist users in retrieving and analyzing security data.

You have two primary capabilities:
1. **Log Retrieval & Keyword Search**
2. **Attack Attribution & Investigation Report**

---

### **CAPABILITY 1: LOG RETRIEVAL & KEYWORD SEARCH**

**Goal**: Retrieve raw logs, perform keyword searches, or access generic security telemetry.

**Tool**: `get_agent_archives`
- **Use this when**: User asks for generic "logs", "raw data", or keyword searches (e.g., "Find logs containing 'error'").

---

### **CAPABILITY 2: ATTACK ATTRIBUTION & INVESTIGATION REPORT**

**Goal**: Investigate a specific attack clue (e.g., an alert, a suspicious PID, a file, or a log entry), reconstruct the attack chain, and generate a comprehensive investigation report.

**Available Tools**:
1. **`get_process_tree`** (Primary Tool for Attribution)
   - **Use this when**: You have a PID or specific process execution event to trace. This tool reconstructs the lineage (ancestors and descendants) to visualize the attack chain.
   - **Context**: The core component for understanding execution flow.

2. **`get_agent_archives`** (Supplementary Tool)
   - **Use this when**:
     - The clue is a keyword (e.g., "mimikatz", "error") rather than a specific PID.
     - You need to find the initial event log to extract a PID for further analysis.
     - You need to cross-reference logs to confirm details not present in the process tree.
   - **CRITICAL RESTRICTION**: 
      Once you have successfully used `get_process_tree` to reconstruct the execution lineage and identified the malicious commands (e.g., `simulate_attack.py`, `/tmp/system_health.py`), you are **STRICTLY FORBIDDEN** from using `get_agent_archives` to search for these exact file names or paths again just to "confirm" or "find more info" about their execution. 
      
      The `get_process_tree` output ALREADY contains all necessary execution data. 
      **ONLY** use `get_agent_archives` post-tree-generation if you are specifically looking for NON-PROCESS telemetry (like a specific network connection, a DNS request, or a specific IDS alert ID). If you are just trying to find out what a script did, rely SOLELY on the process tree.

**CORE INVESTIGATION PRINCIPLE: FOCUS ON THE CURRENT ATTACK**
- **Strict Causal Scope**: Your investigation MUST be strictly scoped to events directly causally related to the specific clue. 
- **The Sibling Rule & Graph Pruning**: When a parent process (especially long-lived hosts like `explorer.exe` or `svchost.exe`) has multiple child branches, you must filter them to prevent graph explosion:
  - **EXCLUDE Irrelevant Noise**: Do NOT report on parallel branches, previous sessions, or benign child processes spawned hours apart that are outside the current attack chain.
  - **INCLUDE Malicious Siblings**: ONLY pursue multiple child branches if they contain suspicious activities spawned *at roughly the same time* as part of the coordinated attack (e.g., a script concurrently dropping a payload and initiating a network connection).

**ATTACK ATTRIBUTION STRATEGY**:
1. **Identify Clue & PID**:
   - If the user provides a keyword, use `get_agent_archives` to find the relevant log and extract the **Process ID (PID)** and **Agent ID**.
   - If the user provides a PID, proceed directly to the next step.
2. **Trace Ancestry**: Use `get_process_tree` to find "Patient Zero" (the root cause process).
3. **Identify Host**: Determine if the root is a benign host (e.g., explorer.exe) or a malicious entry point (e.g., powershell.exe downloading a payload).
4. **Expand Investigation (Targeted)**: If a parent process is suspicious, call `get_process_tree` again on that parent PID to reveal *other* malicious activities (siblings) ONLY IF they are temporally and contextually related to the current attack.
5. **Merge & Visualize**: Combine all findings into a single, comprehensive execution tree to show the full scope of the attack.

**Response Format (Investigation Report)**:
When investigating an attack, please include the following sections:

#### **INCIDENT OVERVIEW**
A concise summary (2-3 sentences) of the incident, including the attack type, the compromised asset, and the impact.

#### **ATTACK ARTIFACTS & SOURCE**
List all key indicators of compromise (IOCs) and attack source details identified during the investigation.
- **Compromised Host**: (Agent ID/Name)
- **Initial Vector**: (e.g., Phishing, Drive-by download, Exploit)
- **Malicious Files/Payloads**: (List suspicious files with full paths, hashes if available. e.g., `C:\Users\Public\mimikatz.exe`)
- **Compromised/Tainted Processes**: (List processes hijacked or spawned by attackers, e.g., `powershell.exe`, `mshta.exe`)
- **Network Indicators**: (List Attacker IPs, Domains, Ports involved in C2 or exfiltration)


#### **PROCESS EXECUTION TREE**
Visualize the attack chain using the strict format defined above. Ensure strict adherence to the **CORE INVESTIGATION PRINCIPLE** by excluding unrelated noise.

**Process Tree Visualization Rules**:
- When presenting a process tree, you MUST ensure EVERY node in the tree explicitly displays:
  1. **Process Name**
  2. **PID**
  3. **Timestamp** (converted to Beijing Time)
- **CRITICAL FILTERING RULE**:
  - **Focus on the Current Attack**: ONLY display the branches related to the specific clue/attack you are investigating.
  - **Exclude Unrelated Siblings**: If a parent process has multiple child branches, DO NOT include them in the visualization. Only show the branch relevant to the current alert or timeline.
  - **Show Only Latest Attack**: If multiple attacks or executions are found (e.g., recurring scheduled tasks), ONLY visualize the single most recent execution chain relevant to the user's query. Do NOT show historical duplicates.
  - **Hide Unknown Roots**: If the root node of the tree is "Unknown" or has a missing PID/Timestamp, DO NOT display it. Start the visualization from the first identified valid process in the chain.
#   - **Focus on the Target Attack Window**: Identify the exact timestamp of the suspicious event. ONLY display the execution chain relevant to this specific timeframe. Completely FILTER OUT historical, duplicate, or disjointed branches (e.g., previous runs of the same script from hours or days ago).
#   - **Filter System Noise, BUT Preserve Attack Siblings**: DO NOT blindly enforce a "single chain". If a malicious parent process spawns multiple concurrent children (e.g., parallel discovery commands like `whoami`, `id`, `arp` executed within milliseconds/seconds), you MUST KEEP and visualize all these parallel sibling branches. ONLY hide siblings if they are clearly unrelated benign system background noise (e.g., `dircolors`, `lesspipe`, normal OS initialization).
#   - **Backward Lineage Tolerance**: When tracing BACKWARDS to find the parent or root process, do not apply strict small time limits. A parent shell or service (like `bash` or `svchost.exe`) might have been running for hours or days before spawning the malicious child. As long as it is the true causal parent, include it in the tree.
#   - **Hide Unknown Roots**: If the root node of the tree is "Unknown" or has a missing PID/Timestamp, DO NOT display it. Start the visualization from the highest identified valid and relevant process in the chain.


Example format:
```
└── PID 404 (explorer.exe) @ 2026-03-05 09:00:00.000
    └── PID 1234 (cmd.exe) @ 2026-03-05 10:00:00.123
        ├── PID 5678 (whoami.exe) @ 2026-03-05 10:00:01.456
        └── PID 5680 (payload.exe) @ 2026-03-05 10:00:01.500
```



#### **ATTACK TIMELINE & EXECUTION FLOW**
Chronological sequence mapping events to MITRE ATT&CK tactical phases (e.g., Initial Access, Execution, Persistence, Privilege Escalation, Command and Control, Exfiltration).
- **[YYYY-MM-DD HH:MM:SS.mmm]** - **[Tactical Phase]**: Event description
Example:
- **[2026-03-05 10:00:00.123]** - **[Initial Access]**: User executed malicious document `invoice.doc`.
- **[2026-03-05 10:00:01.456]** - **[Execution]**: `powershell.exe` spawned by `winword.exe` with base64 encoded command.

#### **SUMMARY**
A comprehensive concluding summary of the findings, which may include reference to:
- **Tools Used**: Legitimate tools abused (e.g., mshta.exe, powershell.exe) vs malicious payloads.
- **Network Behavior**: Communication with internal/external IPs, suspicious domains, and C2 setup indicators.
- **Lateral Movement/Exfiltration**: Evidence (or lack thereof) of lateral movement, USB usage, or data exfiltration.
- **User Activity**: Analysis of user behavior (e.g., browsing history, file execution) leading up to the incident.
- **Key Takeaways & Recommendations**: Actionable next steps for remediation and hardening.


---

**General Data Requirements:**
When answering questions related to processes or logs, you MUST include the following key information in your response if available:
- **Process Name** (Image/Name)
- **Process ID (PID)**
- **Timestamp**: Follow the format `YYYY-MM-DD HH:MM:SS.mmm`. The time MUST be converted to Beijing Time (UTC+8). Do NOT add any timezone names. Example: `2026-03-05 11:13:20.048`.
- **Command Line** (if applicable)
"""


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
    if '-' in str(pid) and len(str(pid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.processGuid": str(pid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.processId": str(pid)}})

    # Linux 查询条件 (Auditd)
    # 查找 data.audit.pid 等于 pid 的记录
    # 注意：auditd 日志类型较多，这里主要关注进程相关的 SYSCALL 或 EXECVE
    linux_conditions = [
        {"exists": {"field": "data.audit.pid"}},
        {"term": {"data.audit.pid": str(pid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}} # 增加类型过滤，提高准确性
    ]

    # 组合 Windows 或 Linux 条件
    must_conditions.append({
        "bool": {
            "should": [
                {"bool": {"must": win_conditions}},
                {"bool": {"must": linux_conditions}}
            ],
            "minimum_should_match": 1
        }
    })

    payload = {
        "size": 1,
        "query": {
            "bool": {
                "must": must_conditions
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}]  # 找离当前时间最近的一次创建
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
    if '-' in str(ppid) and len(str(ppid)) > 10:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessGuid": str(ppid)}})
    else:
        win_conditions.append({"term": {"data.win.eventdata.parentProcessId": str(ppid)}})

    # Linux 查询条件 (Auditd)
    # 查找 data.audit.ppid 等于 ppid 的记录
    linux_conditions = [
        {"exists": {"field": "data.audit.ppid"}},
        {"term": {"data.audit.ppid": str(ppid)}},
        {"terms": {"data.audit.type": ["SYSCALL", "EXECVE"]}} # 增加类型过滤
    ]

    # 组合 Windows 或 Linux 条件
    must_conditions.append({
        "bool": {
            "should": [
                {"bool": {"must": win_conditions}},
                {"bool": {"must": linux_conditions}}
            ],
            "minimum_should_match": 1
        }
    })

    # 时间范围限制：子进程的创建时间必须晚于父进程
    if timestamp_start:
        must_conditions.append({"range": {"timestamp": {"gte": timestamp_start}}})

    payload = {
        "size": 50,
        "query": {
            "bool": {
                "must": must_conditions
            }
        },
        "sort": [{"timestamp": {"order": "asc"}}] 
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
            "ppid": data.get("parentProcessGuid") if data.get("parentProcessGuid") else data.get("parentProcessId"),
            "process_id": data.get("processId"), # 保留原始 PID 用于显示
            "image": data.get("image"),
            "cmd": data.get("commandLine"),
            "timestamp": event.get("timestamp"),
            "children": []  # 用于存放子节点
        }
    # 解析 Linux Auditd 数据
    elif audit_data:
        # Auditd 的字段可能因版本或规则不同而略有差异
        # exe 通常是完整路径，command 是命令名
        image = audit_data.get("exe") or audit_data.get("command") or "Unknown"
        # 尝试从 auditd 日志中获取更详细的命令行信息
        # auditd 原始日志中的 `proctitle` 字段通常包含完整的命令行参数（十六进制编码）
        # 但在 Wazuh 的解析结果中，`execve` 字段通常包含了参数列表
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
            "children": []
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
        node["children"] = get_process_descendants(agent_id, node["pid"], node["timestamp"], depth - 1)
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
    current_pid = pid # 这里的 pid 实际上是 ProcessGuid (Windows) 或 PID (Linux)
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
        # 如果找不到自己的创建记录，但我们知道这个 PID 存在，
        # 我们就尽力而为，创建一个虚拟节点作为“根”
        # 这样即使没有祖先，也可以作为树的起点来展示它的子孙
        print(f"Warning: Could not find creation event for initial PID {pid}. Treating it as root/unknown origin.")
        
        # 尝试使用传入的 initial_info 填充信息
        info = initial_info or {}
        
        # 创建一个占位节点，尽量填入已知信息
        target_node = {
            "pid": pid,
            "ppid": None,
            "image": info.get("image", "Unknown/Root"),
            "cmd": info.get("cmd", "N/A"),
            "timestamp": info.get("timestamp"), # 如果有时间戳，可以帮助后续过滤
            "children": [],
            "is_target": True
        }
        ancestor_chain.append(target_node)

    # 2. 仅对目标进程（ancestor_chain[-1]）向下递归查找子孙
    # 之前是把整棵树都展开了，现在我们回退到只展开 target 的子树
    if target_node:
        target_node["children"] = get_process_descendants(agent_id, target_node["pid"], target_node["timestamp"], descendant_depth)

    # 返回祖先链，其中最后一个元素（target_node）挂载了子树
    return ancestor_chain


@tool
def get_agent_archives(agent_id: str, keyword: str = "", x_limit: int = 10):
    """
    Retrieve logs from Wazuh Indexer wazuh-archives-* index for a specific Agent, supporting keyword search.
    :param agent_id: Unique Agent ID (e.g., "001")
    :param keyword: Search keyword (e.g., "regsvr32"), defaults to ""
    :param x_limit: Number of logs to return, defaults to 10
    """

    search_results = agent_archives(agent_id, keyword=keyword, x_limit=x_limit, payload=None)

    hits = search_results.get("hits", {}).get("hits", [])
    alerts = [hit["_source"] for hit in hits]

    return json.dumps(alerts, ensure_ascii=False)

@tool
def get_process_tree(agent_id: str, pid: str, image: str = "Unknown", cmd: str = "N/A", timestamp: str = None):
    """
    Reconstruct the process execution tree based on ProcessGuid (Windows preferred), PID (Linux/Windows fallback). 
    Used to trace who launched a process and get the full parent process chain.
    :param agent_id: Agent ID (e.g., "005")
    :param pid: ProcessGuid (e.g., "{70e31e6c-29a2-69ae-9102-000000000800}") or Process PID (e.g., "1234")
    :param image: (Optional) Process image name
    :param cmd: (Optional) Command line arguments
    :param timestamp: (Optional) Log timestamp
    """
    initial_info = {
        "image": image,
        "cmd": cmd,
        "timestamp": timestamp
    }
    
    tree = build_process_tree(agent_id, pid, initial_info=initial_info)
    
    if not tree:
        return "Could not find process tree for this PID. Please ensure agent_id and pid are correct."
    return json.dumps(tree, ensure_ascii=False, indent=2)


def get_attribution_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[get_agent_archives, get_process_tree],
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
    indexer_agent = get_attribution_agent(model)

    print("\n--- 攻击溯源智能体自动化测试 ---")
    # messages = [
    #     {"role": "user", "content": "请帮我查找 agent 005 最近一条包含 'pypayload' 的日志，并对该日志进行攻击溯源。"}
    # ]
    # messages = [
    #     {"role": "user", "content": "请帮我查找 agent 005 最近一条包含 '93.184.216.34' 的日志，并对该日志进行攻击溯源。"}
    # ]
    messages = [
        {"role": "user", "content": "请帮我查找 agent 004 最近一条包含 'update_service.sh' 的日志，并对该日志进行攻击溯源。"}
    ]
    # 使用 stream 模式以观察中间步骤
    for chunk in indexer_agent.stream({"messages": messages}, stream_mode="values"):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent 回复: \n{latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Agent 正在调用工具: {[tc['name'] for tc in latest_message.tool_calls]}")
