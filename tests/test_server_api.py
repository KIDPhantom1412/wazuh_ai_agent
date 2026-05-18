import json
import pathlib
import re
from urllib.parse import parse_qs, urlparse

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


@pytest.mark.usefixtures("mock_auth")
def test_query_rules_with_filters(demo_wazuh_api_response, requests_mock):
    demo_rules = demo_wazuh_api_response("rules_query_response")
    requests_mock.get(re.compile(r"^https?://[^/:]+:\d+/rules.*$"), json=demo_rules)
    from wazuh_api.server_api import query_rules

    response = query_rules(
        rule_ids=[5764, 5710],
        search="ssh",
        group="sshd",
        level="8-12",
        filename=["0575-win-base_rules.xml"],
        mitre="T1110",
        limit=5,
        select="id,level,description",
        sort="+id",
    )

    assert response["data"]["total_affected_items"] == 1
    query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert query_params["rule_ids"] == ["5764,5710"]
    assert query_params["search"] == ["ssh"]
    assert query_params["group"] == ["sshd"]
    assert query_params["level"] == ["8-12"]
    assert query_params["filename"] == ["0575-win-base_rules.xml"]
    assert query_params["mitre"] == ["T1110"]
    assert query_params["limit"] == ["5"]
    assert query_params["select"] == ["id,level,description"]
    assert query_params["sort"] == ["+id"]


@pytest.mark.usefixtures("mock_auth")
def test_rule_collection_endpoints(requests_mock):
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/files(\?.*)?$"),
        json={"data": {"affected_items": [{"filename": "local_rules.xml"}]}, "error": 0},
    )
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/groups(\?.*)?$"),
        json={"data": {"affected_items": [{"name": "sshd"}]}, "error": 0},
    )
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/requirement/pci_dss(\?.*)?$"),
        json={"data": {"affected_items": [{"id": 5764}]}, "error": 0},
    )
    from wazuh_api.server_api import get_rules_by_requirement, list_rule_files, list_rule_groups

    list_rule_files(search="local", limit=3)
    file_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/files"
    assert file_query_params["search"] == ["local"]
    assert file_query_params["limit"] == ["3"]

    list_rule_groups(limit=2)
    group_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/groups"
    assert group_query_params["limit"] == ["2"]

    get_rules_by_requirement("pci_dss", limit=1)
    requirement_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/requirement/pci_dss"
    assert requirement_query_params["limit"] == ["1"]


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_file_endpoint(requests_mock):
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/files/local_rules\.xml(\?.*)?$"),
        json={"data": {"affected_items": [{"filename": "local_rules.xml"}]}, "error": 0},
    )
    from wazuh_api.server_api import get_rule_file

    response = get_rule_file("local_rules.xml")

    assert response["error"] == 0
    assert requests_mock.last_request.path == "/rules/files/local_rules.xml"
