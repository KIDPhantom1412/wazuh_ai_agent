import os
import sys
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage

_MISSING = object()


class MockModel(BaseChatModel):
    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        content = ""

        # Mock responses based on context (simplified)
        system_prompt = str(messages[0].content)
        if "extract necessary parameters" in system_prompt:
            content = '{"agent_id": "001", "time_range": "now-24h", "filters": {}, "event_type": "ssh_failed", "description": "SSH failed", "missing_parameters": []}'
        elif "Extract Wazuh rule query filters" in system_prompt:
            latest_user = str(messages[-1].content).lower()
            if "groups" in latest_user:
                content = '{"query_type": "groups", "rule_ids": null, "search": null, "group": null, "level": null, "filename": null, "relative_dirname": null, "status": null, "pci_dss": null, "gdpr": null, "gpg13": null, "hipaa": null, "tsc": null, "mitre": null, "requirement": null, "limit": 10, "offset": null, "select": null, "sort": null, "q": null, "list_all": true}'
            elif "files" in latest_user:
                content = '{"query_type": "files", "rule_ids": null, "search": null, "group": null, "level": null, "filename": null, "relative_dirname": null, "status": null, "pci_dss": null, "gdpr": null, "gpg13": null, "hipaa": null, "tsc": null, "mitre": null, "requirement": null, "limit": 10, "offset": null, "select": null, "sort": null, "q": null, "list_all": true}'
            elif "requirement" in latest_user:
                content = '{"query_type": "requirement", "rule_ids": null, "search": null, "group": null, "level": null, "filename": null, "relative_dirname": null, "status": null, "pci_dss": null, "gdpr": null, "gpg13": null, "hipaa": null, "tsc": null, "mitre": null, "requirement": "pci_dss", "limit": 10, "offset": null, "select": null, "sort": null, "q": null, "list_all": false}'
            else:
                content = '{"query_type": "rules", "rule_ids": 5764, "search": null, "group": null, "level": null, "filename": null, "relative_dirname": null, "status": null, "pci_dss": null, "gdpr": null, "gpg13": null, "hipaa": null, "tsc": null, "mitre": null, "requirement": null, "limit": 10, "offset": null, "select": null, "sort": null, "q": null, "list_all": false}'
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
            latest_user = str(messages[-1].content)
            if "query" in latest_user.lower() or "查" in latest_user:
                content = '{"next_step": "query_rule"}'
            elif "verify" in latest_user.lower() or "yes" in latest_user.lower():
                content = '{"next_step": "verify_rule"}'
            else:
                content = '{"next_step": "extract_requirements"}'
        else:
            content = "Mock response"

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

    @property
    def _llm_type(self):
        return "mock"


def test_graph():
    mocked_wazuh_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.server_api": MagicMock(),
        "wazuh_api.indexer_api": MagicMock(),
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_wazuh_modules}
    sys.modules.update(mocked_wazuh_modules)
    try:
        from agents.rule_agent.rule_agent import get_rule_agent
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module

    model = MockModel()
    app = get_rule_agent(model)

    # Test 1: Initial Request
    initial_state = {
        "messages": [HumanMessage(content="Create a rule for SSH failure on agent 001")]
    }

    # We need to mock the API return values
    with (
        patch(
            "agents.rule_agent.nodes.get_agents_overview",
            return_value={"data": "mock_overview"},
        ),
        patch(
            "agents.rule_agent.nodes.get_config_agentless",
            return_value={"data": "mock_agentless"},
        ),
        patch(
            "agents.rule_agent.nodes.search_archived_logs",
            return_value={"hits": {"hits": [{"_source": {"message": "ssh failed"}}]}},
        ),
    ):

        result = app.invoke(initial_state)
        # Test 2: Verify Rule (Simulate user saying "Yes")
        state_with_rule = result.copy()
        state_with_rule["messages"].append(HumanMessage(content="Yes, verify it."))

        with (
            patch("agents.rule_agent.nodes.upload_rule_file", return_value={"error": 0}),
            patch("agents.rule_agent.nodes.restart_manager", return_value={"error": 0}),
            patch("agents.rule_agent.nodes.validate_configuration", return_value={"error": 0}),
            patch(
                "agents.rule_agent.nodes.run_logtest",
                return_value={"data": {"output": {"rule": {"id": 110001}}}},
            ),
        ):
            app.invoke(state_with_rule)


def _load_rule_agent_for_test():
    mocked_wazuh_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.server_api": MagicMock(),
        "wazuh_api.indexer_api": MagicMock(),
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_wazuh_modules}
    sys.modules.update(mocked_wazuh_modules)
    try:
        from agents.rule_agent.rule_agent import get_rule_agent
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
    return get_rule_agent


def test_rule_agent_queries_existing_rule():
    get_rule_agent = _load_rule_agent_for_test()
    app = get_rule_agent(MockModel())
    query_response = {
        "data": {
            "affected_items": [
                {
                    "id": 5764,
                    "level": 10,
                    "description": "Multiple SSH login attempts using non-existent usernames.",
                    "groups": ["syslog", "sshd"],
                    "filename": "0575-win-base_rules.xml",
                }
            ],
            "total_affected_items": 1,
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": "All selected rules were returned",
        "error": 0,
    }

    with patch("agents.rule_agent.nodes.query_rules", return_value=query_response) as mock_query:
        result = app.invoke({"messages": [HumanMessage(content="query rule 5764")]})

    assert mock_query.call_args.kwargs["rule_ids"] == 5764
    assert "5764" in result["messages"][-1].content
    assert "Level: 10" in result["messages"][-1].content
    assert "Multiple SSH login attempts" in result["messages"][-1].content


def test_rule_agent_query_handles_empty_result():
    get_rule_agent = _load_rule_agent_for_test()
    app = get_rule_agent(MockModel())
    empty_response = {
        "data": {
            "affected_items": [],
            "total_affected_items": 0,
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": "All selected rules were returned",
        "error": 0,
    }

    with patch("agents.rule_agent.nodes.query_rules", return_value=empty_response):
        result = app.invoke({"messages": [HumanMessage(content="query rule 5764")]})

    assert "没有查询到匹配的 Wazuh 规则" in result["messages"][-1].content


def test_rule_agent_queries_rule_groups():
    get_rule_agent = _load_rule_agent_for_test()
    app = get_rule_agent(MockModel())
    group_response = {
        "data": {
            "affected_items": [{"name": "sshd", "count": 12}],
            "total_affected_items": 1,
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": "All selected rule groups were returned",
        "error": 0,
    }

    with patch(
        "agents.rule_agent.nodes.list_rule_groups", return_value=group_response
    ) as mock_query:
        result = app.invoke({"messages": [HumanMessage(content="query rule groups")]})

    assert mock_query.call_args.kwargs["limit"] == 10
    assert result["rule_query_result_type"] == "groups"
    assert "规则组" in result["messages"][-1].content
    assert "sshd" in result["messages"][-1].content


def test_rule_agent_surfaces_rule_query_api_errors():
    get_rule_agent = _load_rule_agent_for_test()
    app = get_rule_agent(MockModel())
    error_response = {
        "data": {
            "affected_items": [],
            "total_affected_items": 0,
            "total_failed_items": 1,
            "failed_items": [{"error": {"code": 1600}, "id": ["bad"]}],
        },
        "message": "Invalid query",
        "error": 1600,
    }

    with patch("agents.rule_agent.nodes.query_rules", return_value=error_response):
        result = app.invoke({"messages": [HumanMessage(content="query rule 5764")]})

    assert "查询 Wazuh 规则失败" in result["messages"][-1].content
    assert "1600" in result["messages"][-1].content
