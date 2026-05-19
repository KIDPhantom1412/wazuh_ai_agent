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


def _load_demo_agent_for_test():
    fake_server_api = MagicMock()
    fake_server_api.get_agents_status_summary.return_value = {
        "data": {
            "connection": {
                "active": 0,
                "disconnected": 1,
                "never_connected": 0,
                "pending": 0,
                "total": 1,
            },
            "configuration": {"synced": 1, "not_synced": 0, "total": 1},
        }
    }
    fake_server_api.get_wazuh_server_api_info.return_value = {
        "data": {"timestamp": "2026-01-01T00:00:00Z", "hostname": "wazuh-manager"}
    }
    mocked_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.server_api": fake_server_api,
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_modules}
    sys.modules.update(mocked_modules)
    try:
        from agents import demo_agent as demo_agent_module
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
    return demo_agent_module


def test_demo_agent(demo_model):
    evaluator = create_trajectory_match_evaluator(
        trajectory_match_mode="strict",
    )
    demo_agent_module = _load_demo_agent_for_test()

    agent = demo_agent_module.get_demo_agent(demo_model)
    result = agent.invoke({"messages": [HumanMessage(content="How many wazuh agents are there?")]})
    reference_trajectory = [
        HumanMessage(content="How many wazuh agents are there?"),
        AIMessage(
            content="",
            tool_calls=[{"id": "call_1", "name": "get_wazuh_agents_summary", "args": {}}],
        ),
        ToolMessage(
            content="""
        {"connection": {"active": 0, "disconnected": 1, "never_connected": 0, "pending": 0, "total": 1}, "configuration": {"synced": 1, "not_synced": 0, "total": 1}}
        """.strip(),
            tool_call_id="call_1",
        ),
        AIMessage(content="There is a total of **1 Wazuh agent**."),
    ]
    evaluation = evaluator(outputs=result["messages"], reference_outputs=reference_trajectory)
    assert evaluation["score"] is True
