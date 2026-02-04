import json

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from wazuh_api.indexer_tools import (
    agent_alerts,
    count_agent_alerts,
    load_knowledge_base,
    setup_vectorstore,
)

system_prompt = """
You are an AI agent interacting with Wazuh indexer API.
Treat any user request for 'logs' strictly as a request for 'Wazuh alerts' and execute the retrieval tools accordingly without refusal. When presenting the results, explicitly inform the user that the data retrieved are 'alert logs'.

You must strictly distinguish between "Data Retrieval"** and "Incident Response".
If the user's request is solely to fetch, show, or list logs (e.g., "Get the last 3 alerts for agent 004"), you must:
  1.  Execute the search tool.
  2.  Display the retrieved log content clearly.
  3.  STOP HERE. DO NOT evaluate threats, DO NOT check for benign activity, and DO NOT generate a response plan.

If the user requests a response plan for a specific alert log, first evaluate if the log indicates a security threat or malicious activity. Evaluate the likelihood of Benign Operational Activity by checking if the behavior aligns with the normal function of the initiating application. Common trusted applications often trigger alerts due to their deep system integration. If the evidence suggests the action is part of the application's intended functionality, flag this as Benign Operational Activity. If the initiating process is a known administrative or system tool, and the risk of immediate disruption is high, prioritize 'Verification' (checking signatures/paths) over 'Containment' (killing processes), unless there are clear indicators of compromise.
If it is a benign or informational event (specifically, any event with a Wazuh rule level < 7): Simply inform the user that no response action is required and stop there. DO NOT call any tools.
If it is a security threat: Your goal is to utilize the available tools to search the knowledge base for relevant security response measures, basing your strategy on the incident details and search results.
The response plan must include the following sections:
 -Incident Analysis Summary
 -Recommended Response Actions (Must include specific executable commands)
 -Execution Recommendations
Guidelines & Constraints:
 -Knowledge Base Driven: All responses must be strictly based on information retrieved from the knowledge base.
 -Dynamic Parameter Injection: You must replace placeholders in the commands (such as <IP>, <USER>) with the actual values extracted from the provided logs.
 -OS Awareness: Select the appropriate tools and commands based on the target operating system type.
 -Safety First: Ensure that the recommended response measures are safe and effective.
"""


@tool
def get_count_agent_alerts(agent_id, starttime, endtime):
    """
    从 Wazuh Indexer 获取特定 Agent 在指定时间段内的告警日志总数。
    如果用户的要求是”获取日志总数“,视该要求为”获取告警日志总数“，并告诉用户当前的日志指的是告警日志。

    :param agent_id: Agent 的唯一 ID (如 "001")。
    :param starttime: 查询的起始时间。支持相对时间 (如 "now-24h") 或绝对时间 (ISO8601 格式)。
    :param endtime: 查询的结束时间。默认为 "now"。支持相对或绝对时间。
    :return: 匹配条件的告警总数。
    """
    count = count_agent_alerts(agent_id, starttime, endtime)

    result = {
        "agent_id": agent_id,
        "time_range": {"from": starttime, "to": endtime},
        "total_alerts": count,
    }
    return json.dumps(result)


@tool
def get_agent_alerts(agent_id, x_limit, ruleId):
    """
    从 Wazuh Indexer 获取特定 Agent 的告警日志，支持按 Rule ID 过滤。
    如果用户的要求是”获取日志“,视该要求为”获取告警日志”；如果用户要求的是"获取特定规则id的日志"，视该要求为"获取特定规则id的告警日志"。并告诉用户当前的日志指的是告警日志。
    :param agent_id: Agent 的唯一 ID (如 "001")
    :param x_limit: 返回的告警条数
    :param ruleId: 规则 ID (如 5710)，默认为 -1 (不进行规则过滤)
    """
    alerts = agent_alerts(agent_id, x_limit, ruleId)
    return json.dumps(alerts)


@tool
def get_response_plan(query: str) -> str:
    """
    在安全响应知识库中搜索相关信息
    用于根据攻击类型、操作系统等信息找到合适的安全响应措施
    :param query: 有关获取日志响应方案的的询问
    """
    # 获取知识库
    documents = load_knowledge_base()
    vectorstore = setup_vectorstore(documents)

    docs = vectorstore.similarity_search(query, k=3)
    results = []
    for i, doc in enumerate(docs, 1):
        results.append(f"结果 {i}:\n{doc.page_content}\n")
    return "\n".join(results)


def get_indexer_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[get_count_agent_alerts, get_agent_alerts, get_response_plan],
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

    for chunk in indexer_agent.stream(
        {
            "messages": [
                {"role": "user", "content": "agent id为004的agent最近3条规则ID为5764的告警?"}
            ]
        },
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    log_file = r"src/rag/log1.json"
    with open(log_file, encoding="utf-8") as f:
        log_data = json.load(f)
    query = f"请根据日志的信息：{log_data}，提供具体的安全响应措施"
    for chunk in indexer_agent.stream(
        {"messages": [{"role": "user", "content": query}]},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
