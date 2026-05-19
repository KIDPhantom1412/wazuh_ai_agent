import sys
from unittest.mock import MagicMock

import pytest
from agentevals.trajectory.match import create_trajectory_match_evaluator
from langchain.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI

from core.config import settings

_MISSING = object()


@pytest.fixture
def demo_model():
    return ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )


def _load_indexer_agent_for_test():
    fake_indexer_api = MagicMock()
    fake_indexer_api.count_agent_alerts.return_value = {"count": 133}
    fake_indexer_api.agent_alerts.return_value = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "agent": {
                            "id": "004",
                            "name": "UbuntuSSH",
                            "ip": "192.168.109.135",
                        },
                        "data": {"srcuser": "admin0", "srcip": "192.168.109.130"},
                        "rule": {
                            "id": "5764",
                            "description": "Multiple SSH login attempts using non-existent usernames.",
                        },
                    }
                }
            ]
        }
    }
    fake_indexer_api.agent_archives.return_value = {"hits": {"hits": []}}
    mocked_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.indexer_api": fake_indexer_api,
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_modules}
    sys.modules.update(mocked_modules)
    try:
        from agents import indexer_agent as indexer_agent_module
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
    return indexer_agent_module


def test_indexer_agent(demo_model):

    # test1
    evaluator = create_trajectory_match_evaluator(
        trajectory_match_mode="strict",
    )

    indexer_agent_module = _load_indexer_agent_for_test()

    agent = indexer_agent_module.get_indexer_agent(demo_model)

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
                        "x_limit": "3",
                        "ruleId": "5764",
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
            content='Here are the alert logs for Agent 004 with Rule ID 5764:\n```json\n[{"agent": {"id": "004", "name": "UbuntuSSH", "ip": "192.168.109.135"}, "data": {"srcuser": "admin0", "srcip": "192.168.109.130"}, "rule": {"id": "5764", "description": "Multiple SSH login attempts using non-existent usernames."}}]\n```'
        ),
    ]
    evaluation = evaluator(outputs=result["messages"], reference_outputs=reference_trajectory)
    assert evaluation["score"] is True
