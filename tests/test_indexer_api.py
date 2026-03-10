import json
import pathlib
import re

import pytest


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


def test_count_agent_alerts(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("count_agent_alerts_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-.*/_count$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import count_agent_alerts

    response = count_agent_alerts("001","now-1h", "now")
    assert response["count"] == 2116


def test_agent_alerts(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("agent_alerts_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-.*/_search$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import agent_alerts

    response = agent_alerts("004",x_limit=1, ruleId=5764)
    hits = response.get("hits", {}).get("hits", [])
    assert len(hits) == 1
    assert hits[0]["_source"]["agent"]["id"] == "004"
    assert hits[0]["_source"]["rule"]["id"] == "5764"


def test_agent_archives(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("agent_archives_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import agent_archives

    response = agent_archives("005",keyword="whoami", x_limit=1)
    hits = response.get("hits", {}).get("hits", [])
    assert len(hits) == 1
    assert hits[0]["_source"]["agent"]["id"] == "005"