import logging
from collections.abc import Sequence
from typing import Annotated, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.output_parsers import PydanticOutputParser
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    next: str


class RouteInfo(BaseModel):
    instruction: str = Field(
        description="交给下一个智能体的具体任务说明或问题（例如：'请查找关于malicious.exe的日志并返回PID'）。如果是FINISH，则写总结。"
    )
    next: Literal["indexer", "response", "attribution", "FINISH"] = Field(
        description="决定下一个执行的智能体，必须是 'indexer', 'response', 'attribution' 或 'FINISH' 中的一个"
    )


parser = PydanticOutputParser(pydantic_object=RouteInfo)

system_prompt_supervisor = """
你是 Wazuh 安全运营中心 (SOC) 的主管。你需要协调三名专职 AI 员工来满足用户的安全请求。

### 员工的能力与职责
1. 'indexer'：专门负责从 Wazuh 检索数据、提取PID、构建并输出底层原始进程树数据。注意，你必须严格区分它要检索的数据类型：
   - **普通日志 (Raw Logs / Archives)**：当用户要求查找包含特定关键词（如某个进程名）的“日志”时，这是通用检索。
   - **告警日志 (Security Alerts)**：仅当用户明确提到“告警”、“警报”、“规则告警”时，才属于安全告警检索。
   - 【注意】：indexer 返回的仅仅是“数据原材料”，绝不等于攻击溯源报告。
2. 'attribution'：专门负责阅读进程树和日志，进行深度的攻击溯源分析，生成包含 MITRE ATT&CK 映射的调查报告。
3. 'response'：专门负责在拿到日志证据或溯源报告后，查阅安全响应知识库，并出具具体的处置命令和响应方案。

### 任务分解与按需派发 (核心逻辑)
面对用户的多步请求，你必须将其分解为严格的先后步骤。在派发任务时，必须用简练的语言写下明确的指令。
【极其重要】：**并非所有请求都需要经历“查询 -> 溯源 -> 响应”的完整流水线！** 你必须严格根据用户提出的具体诉求按需派发，绝不能擅自加戏：
- 场景 A：用户只说“查询包含 xxx 的日志”
  - 路径：'indexer' -> FINISH
- 场景 B：用户说“查询日志并给出处置建议”
  - 路径：'indexer' -> 'response' -> FINISH（完全跳过溯源）
- 场景 C：用户说“查日志，做攻击溯源，并给出响应方案”
  - 路径：'indexer' -> 'attribution' -> 'response' -> FINISH

### 路由规则 (严格基于当前对话历史判断)
- **步骤 1 (取证)**：如果用户的请求包含查询数据或构建进程树，且当前历史中【还没有】对应的线索证据，请优先分配给 'indexer'。
- **步骤 2 (溯源-仅限被要求时)**：如果历史中已经有了 indexer 提供的基础数据/进程树，且用户在提问中【明确要求】进行“攻击溯源”、“深度分析”或生成“调查报告”，但历史中还没有 attribution 出具的分析，请分配给 'attribution'。若用户没提溯源，绝对不要调此节点！
- **步骤 3 (处置-仅限被要求时)**：如果用户【明确要求】提供“响应方案”、“处置建议”，并且前置的取证（或溯源，如果用户有要求的话）已经完成，请分配给 'response'。
- **结案**：如果用户的各项具体诉求均已由对应专员处理完毕，输出 'FINISH'。

### 强制输出格式：
你必须严格按照以下 JSON 格式输出你的决定，不要包含任何 markdown 标记（如 ```json），直接输出纯 JSON 字符串：
{
    "instruction": "填写交给该员工的具体问题或指令（严格保持用词的准确性，区分普通日志与告警）",
    "next": "填写 indexer, response, attribution 或 FINISH"
}
"""


def get_supervisor_graph(model: BaseChatModel, indexer_agent, response_agent, attribution_agent):

    def supervisor_node(state: AgentState):
        logger.info("\n--- [主管 (Supervisor)] 正在审阅状态并分配任务 ---")

        messages_history = list(state["messages"])

        prompt = [{"role": "system", "content": system_prompt_supervisor}] + messages_history

        raw_response = model.invoke(prompt)
        content = raw_response.content.strip()

        # 清理可能存在的 markdown 格式
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        try:
            parsed_result = parser.invoke(content)
            next_node = parsed_result.next
            instruction = parsed_result.instruction
        except Exception:
            logger.warning(f"Pydantic 解析失败，尝试手动兜底。模型原始输出: {content}")
            instruction = "请继续处理用户的请求"
            if "indexer" in content.lower():
                next_node = "indexer"
            elif "response" in content.lower():
                next_node = "response"
            elif "attribution" in content.lower():
                next_node = "attribution"
            else:
                next_node = "FINISH"

        logger.info(f"--- [主管 (Supervisor)] 决定将任务交由: {next_node} 执行 ---")

        # 🌟 3. 核心机制：将主管的指令包装成消息传递下去
        if next_node != "FINISH":
            return {
                "next": next_node,
                "messages": [HumanMessage(content=f"【主管下发的子任务】: {instruction}")],
            }
        else:
            return {"next": next_node}

    def indexer_node(state: AgentState):
        logger.info("\n--- [查询专员 (Indexer)] 正在检索 Wazuh 数据 ---")
        result = indexer_agent.invoke({"messages": state["messages"]})
        return {"messages": [result["messages"][-1]]}

    def response_node(state: AgentState):
        logger.info("\n--- [响应专员 (Response)] 正在查阅知识库生成处置方案 ---")
        result = response_agent.invoke({"messages": state["messages"]})
        return {"messages": [result["messages"][-1]]}

    def attribution_node(state: AgentState):
        logger.info("\n--- [溯源专家 (Attribution)] 正在进行深度溯源分析 ---")
        result = attribution_agent.invoke({"messages": state["messages"]})
        return {"messages": [result["messages"][-1]]}

    builder = StateGraph(AgentState)
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("indexer", indexer_node)
    builder.add_node("response", response_node)
    builder.add_node("attribution", attribution_node)

    builder.add_edge("indexer", "supervisor")
    builder.add_edge("response", "supervisor")
    builder.add_edge("attribution", "supervisor")

    builder.add_conditional_edges(
        "supervisor",
        lambda state: state["next"],
        {"indexer": "indexer", "response": "response", "attribution": "attribution", "FINISH": END},
    )

    builder.add_edge(START, "supervisor")

    return builder.compile()


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from agents.attribution_agent import get_attribution_agent
    from agents.indexer_agent import get_indexer_agent
    from agents.response_agent import get_response_agent
    from core.config import settings

    # 关闭 httpx 的啰嗦日志
    logging.getLogger("httpx").setLevel(logging.WARNING)

    test_llm = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )

    test_indexer = get_indexer_agent(test_llm)
    test_responder = get_response_agent(test_llm)
    test_attribution = get_attribution_agent(test_llm, test_indexer)

    app = get_supervisor_graph(test_llm, test_indexer, test_responder, test_attribution)

    query = "请帮我查找 Agent 005 最近一条包含 'pypayload' 的日志，然后对其进行攻击溯源，最后告诉我推荐的响应策略。"
    print("\n" + "=" * 80)
    print(f"用户原始提问: {query}")
    print("=" * 80)

    initial_state = {"messages": [HumanMessage(content=query)]}

    for chunk in app.stream(initial_state, {"recursion_limit": 20}, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            print(f"\n[执行节点]: {node_name.upper()}")

            if node_name == "supervisor":
                if "next" in node_state:
                    print(f" 主管路由决策 -> 下一步交由: 【{node_state['next'].upper()}】")

                if "messages" in node_state:
                    for msg in node_state["messages"]:
                        print(f" 主管对员工下达的指令: \033[93m{msg.content}\033[0m")

            else:
                if "messages" in node_state:
                    messages = node_state["messages"]
                    if not isinstance(messages, list):
                        messages = [messages]

                    for msg in messages:
                        if isinstance(msg, AIMessage):
                            if msg.content:
                                print(f"  员工回复: {msg.content}")
                            if hasattr(msg, "tool_calls") and msg.tool_calls:
                                print(f"  准备调用工具: {[tc['name'] for tc in msg.tool_calls]}")
                        elif isinstance(msg, ToolMessage):
                            content_str = str(msg.content)
                            preview = (
                                content_str[:100].replace("\n", " ") + "..."
                                if len(content_str) > 100
                                else content_str
                            )
                            print(f"   工具返回数据: {preview}")
