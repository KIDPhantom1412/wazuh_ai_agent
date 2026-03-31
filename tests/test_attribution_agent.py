import pytest
from langchain.messages import AIMessage, HumanMessage
from langchain_openai import ChatOpenAI

from agents.attribution.attribution_agent import get_attribution_agent
from core.config import settings


@pytest.fixture
def demo_model():
    return ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )


class MockIndexerAgent:
    def invoke(self, inputs):
        messages = inputs.get("messages", [])
        if not messages:
            return {"messages": [AIMessage(content="[]")]}

        last_message = messages[-1]
        if isinstance(last_message, tuple):
            instruction = str(last_message[1]).lower()
        else:
            instruction = str(last_message.content).lower()

        print(f"\n[Mock API 拦截到指令] -> {instruction}")

        parent_keywords = {"creation", "parent", "创建", "父进程"}
        child_keywords = {"child", "子进程", "派生"}
        kwsearch_keywords = {"关键词", "keyword"}
        # 查询进程创建日志
        if "1234" in instruction and any(kw in instruction for kw in parent_keywords):
            mock_creation_json = """
            [
              {
                "agent": {"id": "005"},
                "data": {
                  "win": {
                    "eventdata": {
                      "utcTime": "2026-03-05 10:00:00.000",
                      "processId": "1234",
                      "processGuid": "{70e31e6c-dd9d-69b2-530b-000000000800}",
                      "image": "C:\\Windows\\System32\\cmd.exe",
                      "commandLine": "cmd.exe /c malicious_payload.exe",
                      "parentProcessId": "9991",
                      "parentProcessGuid": "{99921e6c-dd9d-69b2-7777-000000000800}",
                      "parentImage": "C:\\Users\\defin\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
                      "parentCommandLine": "\"C:\\Users\\defin\\AppData\\Local\\Programs\\Python\\Python312\\python.exe\" .\\attack.py"
                    }
                  }
                }
              }
            ]
            """
            return {"messages": [AIMessage(content=mock_creation_json.strip())]}

        # 查询子进程日志
        elif "1234" in instruction or any(kw in instruction for kw in child_keywords):
            # 模拟没有子进程
            return {"messages": [AIMessage(content="[]")]}

        # 关键词查询
        elif any(kw in instruction for kw in kwsearch_keywords):
            return {"messages": [AIMessage(content="该关键词查询不到日志")]}

        # 兜底返回空数据
        return {"messages": [AIMessage(content="[]")]}


@pytest.fixture
def mock_indexer_agent():
    """模拟 API 智能体"""
    return MockIndexerAgent()


def test_attribution_agent(demo_model, mock_indexer_agent):
    agent = get_attribution_agent(demo_model, mock_indexer_agent)

    user_query = "Agent 005上存在可疑进程，PID为1234，帮我对其进行攻击溯源。"
    result = agent.invoke({"messages": [HumanMessage(content=user_query)]})
    messages = result["messages"]
    final_report = messages[-1].content
    print("final_report:", final_report)

    # 验证关键信息是否被提取
    assert "1234" in final_report
    assert "cmd.exe" in final_report
    assert "9991" in final_report or "python.exe" in final_report
    assert "malicious_payload.exe" in final_report
    assert "attack.py" in final_report

    # 验证工具调用
    tool_calls = []
    for m in messages:
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            tool_calls.extend(m.tool_calls)
    assert len(tool_calls) >= 4
