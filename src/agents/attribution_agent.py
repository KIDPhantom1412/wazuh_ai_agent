import logging

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

logger = logging.getLogger(__name__)

system_prompt = r"""
You are an elite Attack Attribution & Forensics AI Expert.
You DO NOT have direct access to any databases, raw logs, or process tree generation tools.
Instead, you have a highly capable assistant called the "API Agent".

### YOUR WORKFLOW:
1. **Delegate Data Gathering**: Use your `investigate_lead` tool to instruct the API Agent to gather evidence.
   - Example command: "Find the latest execution log for 'update_service.sh' on Agent 004, extract its PID, and build the full process tree with command lines."
   - Example command: "Build the process tree for PID 1234 on Agent 001."
2. **Receive & Analyze**: The API Agent will do the dirty work of querying the database and return the raw data and the formatted ASCII process tree to you.
3. **Report Generation**: Analyze the returned process tree (especially the command line arguments) and generate a formal Forensic Investigation Report.

### RESPONSE FORMAT (Investigation Report)
When generating your forensic report, you MUST strictly include the following sections:

#### **INCIDENT OVERVIEW**
A concise summary (2-3 sentences) of the incident, including the attack type, the compromised asset, and the impact.

#### **ATTACK ARTIFACTS & SOURCE**
List all key indicators of compromise (IOCs) and attack source details identified.
- **Compromised Host**: (Agent ID/Name)
- **Initial Vector**: (e.g., Phishing, Drive-by download, Exploit)
- **Malicious Files/Payloads**: (List suspicious files with full paths)
- **Compromised/Tainted Processes**: (List processes hijacked or spawned by attackers)
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
  - **Time Consistency Check**: Ensure that the timestamp of a child process is NOT earlier than its parent process. If you find such a case (e.g., Parent @ 18:55, Child @ 18:16), it indicates a logical error or PID reuse. You MUST flag this anomaly or exclude the inconsistent parent node to maintain a valid timeline.

Example format:
```
└── PID 404 (explorer.exe) @ 2026-03-05 09:00:00.000
    └── PID 1234 (cmd.exe) @ 2026-03-05 10:00:00.123
        ├── PID 5678 (whoami.exe) @ 2026-03-05 10:00:01.456
        └── PID 5680 (payload.exe) @ 2026-03-05 10:00:01.500
```

#### **ATTACK TIMELINE & EXECUTION FLOW**
Chronological sequence mapping events to MITRE ATT&CK tactical phases based on the process tree's command line evidence.
Example:
- **[2026-03-05 10:00:01.456]** - **[Execution / T1059.001]**: `powershell.exe` spawned with hidden window style and base64 encoded command.
- **[2026-03-05 10:00:01.500]** - **[Command and Control / T1105]**: Payload initiated an `Invoke-WebRequest` to a suspicious external IP.

#### **SUMMARY & TAKEAWAYS**
A comprehensive concluding summary of the findings, lateral movement evidence, and actionable next steps.
- **Tools Used**: Legitimate tools abused (e.g., mshta.exe, powershell.exe) vs malicious payloads.
- **Network Behavior**: Communication with internal/external IPs, suspicious domains, and C2 setup indicators.
- **Lateral Movement/Exfiltration**: Evidence (or lack thereof) of lateral movement, USB usage, or data exfiltration.
- **User Activity**: Analysis of user behavior (e.g., browsing history, file execution) leading up to the incident.
- **Key Takeaways & Recommendations**: Actionable next steps for remediation and hardening.

"""


def get_attribution_agent(model: BaseChatModel, indexer_agent):

    @tool
    def investigate_lead(instruction: str) -> str:
        """
        向 Wazuh Indexer API 智能体下达指令，获取日志信息或请求构建进程树。
        :param instruction: 给Wazuh Indexer API智能体的明确指令。
        例如：
        给我获取agent 001的有关dirty.exe关键词的日志
        帮我构建agent 005的pid为1234的进程树
        """
        logger.info(f"call an api agent to investigate: {instruction}")

        # 将指令包装成用户消息，发给 API 智能体
        response = indexer_agent.invoke({"messages": [("user", instruction)]})

        # 提取 API 智能体最后返回的内容（包含画好的进程树或查询结果）
        result = response["messages"][-1].content
        logger.info("receive response from api agent")
        return result

    return create_agent(
        model=model,
        tools=[investigate_lead],
        system_prompt=system_prompt,
    )


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from agents.indexer_agent import get_indexer_agent
    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )

    indexer_agent = get_indexer_agent(model)
    attribution_agent = get_attribution_agent(model, indexer_agent)

    print("\n--- 攻击溯源智能体自动化测试 ---")
    messages = [
        {
            "role": "user",
            # "content": "请帮我查找 agent 005 最近一条包含 'pypayload' 的日志，并对该日志进行攻击溯源，并生成调查报告。",
            "content": "我在agent 005发现一个可疑进程，进程ID为12784，帮我对其进行攻击溯源",
        }
    ]
    # messages = [
    #     {"role": "user", "content": "请帮我查找 agent 005 最近一条包含 '93.184.216.34' 的日志，并对该日志进行攻击溯源。"}
    # ]
    # messages = [
    #     {
    #         "role": "user",
    #         "content": "请帮我查找 agent 004 最近一条包含 'update_service.sh' 的日志，并对该日志进行攻击溯源。",
    #     }
    # ]
    # 使用 stream 模式以观察中间步骤
    for chunk in attribution_agent.stream({"messages": messages}, stream_mode="values"):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent 回复: \n{latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Agent 正在调用工具: {[tc['name'] for tc in latest_message.tool_calls]}")
