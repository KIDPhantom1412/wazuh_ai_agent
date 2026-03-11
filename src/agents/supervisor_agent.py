import logging
from collections.abc import Sequence
from typing import Annotated, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
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
    next: Literal["indexer", "responder", "FINISH"] = Field(
        description="决定下一个执行的智能体，必须是 'indexer', 'responder' 或 'FINISH' 中的一个"
    )


parser = PydanticOutputParser(pydantic_object=RouteInfo)

system_prompt_supervisor = """
你是 Wazuh 安全运营中心 (SOC) 的主管。你需要协调两名专职 AI 员工来满足用户的安全请求：
1. 'indexer'：专门负责从 Wazuh 检索告警日志、统计告警数量或查询原始归档数据。
2. 'responder'：专门负责在拿到日志证据后，查阅安全响应知识库，并出具具体的处置命令和响应方案。

### 路由规则（严格遵守）：
- 如果用户的请求需要查询数据，且对话历史中【还没有】对应的日志证据，请将任务分配给 'indexer'。
- 如果对话历史中【已经有了】相关的日志/告警数据，且用户要求提供响应方案、处置建议，请将任务分配给 'responder'。
- 如果用户的请求既需要查日志又需要响应方案，请【先】分配给 'indexer'。
- 如果用户的诉求已经完全解决，输出 'FINISH'。

### 强制输出格式：
你必须严格按照以下 JSON 格式输出你的决定，不要包含任何 markdown 标记（如 ```json），直接输出纯 JSON 字符串：
{
    "next": "填写 indexer, responder 或 FINISH"
}
"""


# --- 4. 核心工厂函数 ---
def get_supervisor_graph(model: BaseChatModel, indexer_agent, response_agent):

    def supervisor_node(state: AgentState):
        logger.info("\n--- [主管 (Supervisor)] 正在审阅状态并分配任务 ---")

        messages = [{"role": "system", "content": system_prompt_supervisor}] + list(
            state["messages"]
        )

        raw_response = model.invoke(messages)
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
            # 1. 尝试使用 Pydantic Parser 解析
            parsed_result = parser.invoke(content)
            next_node = parsed_result.next
        except Exception:
            logger.warning(f"Pydantic 解析失败，尝试手动兜底。模型原始输出: {content}")
            # 2. 万一解析失败，通过字符串包含关系强制路由
            if "indexer" in content.lower():
                next_node = "indexer"
            elif "responder" in content.lower():
                next_node = "responder"
            else:
                next_node = "FINISH"

        logger.info(f"--- [主管 (Supervisor)] 决定将任务交由: {next_node} 执行 ---")
        return {"next": next_node}

    def indexer_node(state: AgentState):
        logger.info("\n--- [查询专员 (Indexer)] 正在检索 Wazuh 数据 ---")
        result = indexer_agent.invoke({"messages": state["messages"]})
        return {"messages": result["messages"]}

    def responder_node(state: AgentState):
        logger.info("\n--- [响应专员 (Responder)] 正在查阅知识库生成处置方案 ---")
        result = response_agent.invoke({"messages": state["messages"]})
        return {"messages": result["messages"]}

    builder = StateGraph(AgentState)
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("indexer", indexer_node)
    builder.add_node("responder", responder_node)

    builder.add_edge("indexer", "supervisor")
    builder.add_edge("responder", "supervisor")
    builder.add_conditional_edges(
        "supervisor",
        lambda state: state["next"],
        {"indexer": "indexer", "responder": "responder", "FINISH": END},
    )
    builder.add_edge(START, "supervisor")

    return builder.compile()


if __name__ == "__main__":
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_openai import ChatOpenAI

    from agents.indexer_agent import get_indexer_agent
    from agents.response_agent import get_response_agent
    from core.config import settings

    print("正在初始化底层大模型与基础智能体...")
    test_llm = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )

    test_indexer = get_indexer_agent(test_llm)
    test_responder = get_response_agent(test_llm)

    app = get_supervisor_graph(test_llm, test_indexer, test_responder)

    query = "agent 001最近12小时的告警数量"
    print("=" * 60)
    print(f"用户提问: {query}")
    print("=" * 60)

    initial_state = {"messages": [HumanMessage(content=query)]}

    for chunk in app.stream(initial_state, {"recursion_limit": 10}, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            print(f"[当前节点]: {node_name.upper()}")

            # 展示主管的路由决策
            if "next" in node_state:
                print(f"主管决策 -> 下一步交由: 【{node_state['next']}】")

            # 展示专员产生的消息与工具调用
            if "messages" in node_state:
                messages = node_state["messages"]
                if not isinstance(messages, list):
                    messages = [messages]

                for msg in messages:
                    # 解析大模型的回复或工具调用意图
                    if isinstance(msg, AIMessage):
                        if msg.content:
                            print(f"    AI 思考/回复: {msg.content}")
                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            print(f"    准备调用工具: {[tc['name'] for tc in msg.tool_calls]}")
                            for tc in msg.tool_calls:
                                print(f"      - 参数: {tc.get('args')}")

                    # 解析工具的实际返回结果
                    elif isinstance(msg, ToolMessage):
                        content_str = str(msg.content)
                        preview = content_str[:150].replace("\n", " ")
                        if len(content_str) > 150:
                            preview += " ... "
                        print(f"    工具执行完毕, 返回: {preview}")

            print("-" * 60)
