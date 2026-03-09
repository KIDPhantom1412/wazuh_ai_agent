import json
import pathlib
import re

import pytest


@pytest.fixture
def mock_auth(requests_mock):
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "mock_token"}},
        status_code=200,
    )


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


@pytest.mark.usefixtures("mock_auth")
def test_get_wazuh_server_api_info(demo_wazuh_api_response, requests_mock):
    demo_api_info = demo_wazuh_api_response("api_info")
    requests_mock.get(re.compile(r"^https?://[^/:]+:\d+/?$"), json=demo_api_info)
    from wazuh_api.server_api import get_wazuh_server_api_info

    response = get_wazuh_server_api_info()
    assert "api_version" in response["data"]
    assert "hostname" in response["data"]


@pytest.mark.usefixtures("mock_auth")
def test_get_agents_status_summary(demo_wazuh_api_response, requests_mock):
    demo_agents_status_summary = demo_wazuh_api_response("agents_status_summary")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/agents/summary/status/?$"),
        json=demo_agents_status_summary,
    )
    from wazuh_api.server_api import get_agents_status_summary

    response = get_agents_status_summary()
    assert "connection" in response["data"]
    assert "configuration" in response["data"]


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_info_exists(demo_wazuh_api_response, requests_mock):
    demo_rule_info = demo_wazuh_api_response("rule_info_exists")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules\?rule_ids=1002$"), json=demo_rule_info
    )
    from wazuh_api.server_api import get_rule_info

    response = get_rule_info(1002)
    assert response["data"]["total_affected_items"] == 1
    assert response["data"]["affected_items"][0]["id"] == 1002


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_info_not_exists(demo_wazuh_api_response, requests_mock):
    demo_rule_info = demo_wazuh_api_response("rule_info_not_exists")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules\?rule_ids=9999$"), json=demo_rule_info
    )
    from wazuh_api.server_api import get_rule_info

    response = get_rule_info(9999)
    assert response["data"]["total_affected_items"] == 0
