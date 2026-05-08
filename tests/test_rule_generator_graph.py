print("Script started")
import os
import sys
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))
print("Path added")

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage

print("LangChain imported")

# Mock wazuh_api before importing nodes
sys.modules["wazuh_api"] = MagicMock()
sys.modules["wazuh_api.server_api"] = MagicMock()
sys.modules["wazuh_api.indexer_api"] = MagicMock()
print("Modules mocked")

from agents.rule_generator.rule_generator import get_rule_generator_agent

print("Agent imported")


class MockModel(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        content = ""

        # Mock responses based on context (simplified)
        system_prompt = str(messages[0].content)
        print(f"DEBUG: System Prompt: {system_prompt[:50]}...")

        if "extract necessary parameters" in system_prompt:
            content = '{"agent_id": "001", "time_range": "now-24h", "filters": {}, "event_type": "ssh_failed", "description": "SSH failed", "missing_parameters": []}'
        elif "Analyze the following retrieved logs" in system_prompt:
            content = (
                '{"is_feasible": true, "reason": "Logs found", "log_features": "SSH logs present"}'
            )
        elif (
            "Generate the rule" in system_prompt
        ):  # Wait, generate rule prompt has "Generate the rule" in human message, system prompt is "You are a Wazuh Rule Generator Agent"
            content = '{"xml_content": "<group name=\\"ssh\\">...</group>", "rule_id": 110001, "description": "SSH rule"}'
        elif "You are a Wazuh Rule Generator Agent" in system_prompt:
            # This overlaps with requirement extraction if not careful, but requirement has "extract necessary parameters"
            if "Rule Syntax Knowledge" in system_prompt:
                content = '{"xml_content": "<group name=\\"ssh\\">...</group>", "rule_id": 110001, "description": "SSH rule"}'
            else:
                # Fallback for requirement extraction if specific string missing
                content = '{"agent_id": "001", "time_range": "now-24h", "filters": {}, "event_type": "ssh_failed", "description": "SSH failed", "missing_parameters": []}'
        elif "You are a router" in system_prompt:
            content = '{"next_step": "verify_rule"}'
        else:
            content = "Mock response"

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

    @property
    def _llm_type(self):
        return "mock"


def test_graph():
    print("Test graph started")
    model = MockModel()
    app = get_rule_generator_agent(model)

    # Test 1: Initial Request
    print("--- Test 1: Initial Request ---")
    initial_state = {
        "messages": [HumanMessage(content="Create a rule for SSH failure on agent 001")]
    }

    # We need to mock the API return values
    with (
        patch(
            "agents.rule_generator.nodes.get_agents_overview",
            return_value={"data": "mock_overview"},
        ),
        patch(
            "agents.rule_generator.nodes.get_config_agentless",
            return_value={"data": "mock_agentless"},
        ),
        patch(
            "agents.rule_generator.nodes.search_archived_logs",
            return_value={"hits": {"hits": [{"_source": {"message": "ssh failed"}}]}},
        ),
    ):

        result = app.invoke(initial_state)
        print("Final State Keys:", result.keys())
        print("Generated Rule:", result.get("generated_rule"))

        # Test 2: Verify Rule (Simulate user saying "Yes")
        print("\n--- Test 2: Verify Rule ---")
        state_with_rule = result.copy()
        state_with_rule["messages"].append(HumanMessage(content="Yes, verify it."))

        with (
            patch("agents.rule_generator.nodes.upload_rule_file", return_value={"error": 0}),
            patch("agents.rule_generator.nodes.restart_manager", return_value={"error": 0}),
            patch("agents.rule_generator.nodes.validate_configuration", return_value={"error": 0}),
            patch(
                "agents.rule_generator.nodes.run_logtest",
                return_value={"data": {"output": {"rule": {"id": 110001}}}},
            ),
        ):

            result_verify = app.invoke(state_with_rule)
            print("Logtest Passed:", result_verify.get("logtest_passed"))
            print("Final Message:", result_verify["messages"][-1].content)


if __name__ == "__main__":
    try:
        test_graph()
        print("\nTest finished successfully.")
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback

        traceback.print_exc()
