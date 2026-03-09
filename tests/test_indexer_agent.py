import pytest
from agentevals.trajectory.match import create_trajectory_match_evaluator
from langchain.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI

from agents.indexer_agent import get_indexer_agent
from core.config import settings


@pytest.fixture
def demo_model():
    return ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )


def test_indexer_agent(demo_model):
    agent = get_indexer_agent(demo_model)

    # test1
    evaluator = create_trajectory_match_evaluator(
        trajectory_match_mode="strict",
    )

    result = agent.invoke(
        {"messages": [HumanMessage(content="过去1小时内agent id为001的agent产生多少警告?")]}
    )
    reference_trajectory = [
        HumanMessage(content="过去1小时内agent id为001的agent产生多少警告?"),
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_1",
                    "name": "get_count_agent_alerts",
                    "args": {"agent_id": "001", "starttime": "now-1h", "endtime": "now"},
                }
            ],
        ),
        ToolMessage(
            content="133",
            tool_call_id="call_1",
        ),
        AIMessage(content="最近 1 小时告警数: 133"),
    ]
    evaluation = evaluator(outputs=result["messages"], reference_outputs=reference_trajectory)
    assert evaluation["score"] is True

    # test2
    evaluator = create_trajectory_match_evaluator(
        trajectory_match_mode="strict",
    )

    result = agent.invoke(
        {"messages": [HumanMessage(content="agent id为004的agent最近3条规则ID为5764的告警?")]}
    )

    print("\n实际轨迹详情:")
    for i, msg in enumerate(result.get("messages", [])):
        print(f"\n--- 消息 {i} ({type(msg).__name__}) ---")

        if isinstance(msg, HumanMessage):
            print(f"人类消息: {msg.content}")

        elif isinstance(msg, AIMessage):
            print(f"AI消息内容: {msg.content}")
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                print(f"工具调用: {msg.tool_calls}")

        elif isinstance(msg, ToolMessage):
            print(f"工具消息ID: {msg.tool_call_id}")
            content_preview = (
                str(msg.content)[:200] + "..." if len(str(msg.content)) > 200 else str(msg.content)
            )
            print(f"工具内容预览: {content_preview}")

    reference_trajectory = [
        HumanMessage(content="agent id为004的agent最近3条规则ID为5764的告警?"),
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_1",
                    "name": "get_agent_alerts",
                    "args": {
                        "agent_id": "004",
                        "x_limit": 3,
                        "ruleId": 5764,
                    },
                }
            ],
        ),
        ToolMessage(
            content="""[
                {
                    "agent": {"id": "004", "name": "UbuntuSSH", "ip": "192.168.109.135"},
                    "data": {"srcuser": "admin0", "srcip": "192.168.109.130"},
                    "rule": {"id": "5764", "description": "Multiple SSH login attempts using non-existent usernames."}
                }
            ]""",
            tool_call_id="call_1",
        ),
        AIMessage(
            content="根据查询结果，我找到了 agent id 为 004 的 agent 最近 3 条规则 ID 为 5764 的告警。以下是详细信息："
        ),
    ]
    evaluation = evaluator(outputs=result["messages"], reference_outputs=reference_trajectory)
    assert evaluation["score"] is True
