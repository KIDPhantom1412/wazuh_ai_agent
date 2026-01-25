import json

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from wazuh_api.tools import get_agents_status_summary, get_wazuh_server_api_info

system_prompt = """
You are an AI agent interacting with Wazuh server API.
"""


@tool
def get_wazuh_agents_summary():
    """Get the status summary of Wazuh agents."""
    response = get_agents_status_summary()
    return json.dumps(response["data"])


@tool
def get_basic_info():
    """Get current time and the host name of wazuh server."""
    response = get_wazuh_server_api_info()
    return json.dumps(
        {"timestamp": response["data"]["timestamp"], "hostname": response["data"]["hostname"]}
    )


def get_demo_agent(model: BaseChatModel):
    return create_agent(
        model=model, tools=[get_basic_info, get_wazuh_agents_summary], system_prompt=system_prompt
    )


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )
    demo_agent = get_demo_agent(model)
    for chunk in demo_agent.stream(
        {"messages": [{"role": "user", "content": "How many wazuh agents are there?"}]},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
