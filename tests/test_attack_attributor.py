import json
import pathlib
import re

import pytest


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key: str):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


def test_get_archives_by_eventid(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("attribution_archives")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )

    from agents.attack_attribution.log_retrieval_helper import QueryType, get_archives_by_eventid

    result = get_archives_by_eventid.invoke(
        {
            "agent_id": "005",
            "query_type": QueryType.FILE_PATH.value,
            "query_value": "lsass.exe-(PID-712).dmp",
            "event_ids": ["11"],
        }
    )
    logs = json.loads(result)

    assert isinstance(logs, list)
    assert len(logs) >= 1
    assert any(
        any(
            "lsass.exe-(PID-712).dmp"
            in str(log.get("data", {}).get("win", {}).get("eventdata", {}).get(field, ""))
            for field in (
                "image",
                "imageLoaded",
                "sourceImage",
                "targetImage",
                "targetFilename",
                "imagePath",
                "commandLine",
            )
        )
        for log in logs
    )


def test_get_archives_by_keyword(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("attribution_archives")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )

    from agents.attack_attribution.log_retrieval_helper import get_archives_by_keyword

    result = get_archives_by_keyword.invoke(
        {"agent_id": "005", "keyword": "CertUtil.exe", "x_limit": 10}
    )
    logs = json.loads(result)

    assert isinstance(logs, list)
    assert len(logs) >= 2
    assert any("CertUtil.exe" in json.dumps(log, ensure_ascii=False) for log in logs)
