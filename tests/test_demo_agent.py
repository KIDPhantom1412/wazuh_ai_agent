import pytest
from agentevals.trajectory.match import create_trajectory_match_evaluator
from langchain.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI

from core.config import settings


@pytest.fixture
def demo_model():
    return ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )


def test_demo_agent(demo_model):
    evaluator = create_trajectory_match_evaluator(
        trajectory_match_mode="strict",
    )
    from agents.demo_agent import get_demo_agent

    agent = get_demo_agent(demo_model)
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
