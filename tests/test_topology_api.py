import re

from fastapi.testclient import TestClient

import service.topology_service as topology_api


def test_get_topology(requests_mock):
    topology_api.settings.WAZUH_SERVER_API_PROTOCOL = "https"
    topology_api.settings.WAZUH_SERVER_API_HOST = "127.0.0.1"
    topology_api.settings.WAZUH_SERVER_API_PORT = "55000"
    topology_api.settings.WAZUH_SERVER_API_USERNAME = "wazuh"
    topology_api.settings.WAZUH_SERVER_API_PASSWORD = "wazuh-password"
    topology_api.settings.WAZUH_INDEXER_PORT = "9200"
    topology_api.settings.WAZUH_INDEXER_USER = "admin"
    topology_api.settings.WAZUH_INDEXER_PASSWORD = "admin-password"

    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "mock_token"}},
        status_code=200,
    )
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/agents\?limit=100$"),
        json={
            "data": {
                "affected_items": [
                    {"id": "000", "name": "manager-node", "ip": "127.0.0.1", "status": "active"},
                    {"id": "001", "name": "agent-1", "ip": "192.168.1.10", "status": "active"},
                ]
            }
        },
        status_code=200,
    )
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-\*/_search$"),
        json={
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "agent": {"id": "001"},
                            "rule": {"level": 12, "description": "High severity event"},
                        }
                    }
                ]
            }
        },
        status_code=200,
    )

    client = TestClient(topology_api.app)
    response = client.get("/api/topo")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": "000",
            "name": "manager-node",
            "ip": "127.0.0.1",
            "status": "active",
            "has_threat": False,
            "threat_info": "",
            "threat_level": 0,
        },
        {
            "id": "001",
            "name": "agent-1",
            "ip": "192.168.1.10",
            "status": "active",
            "has_threat": True,
            "threat_info": "High severity event",
            "threat_level": 12,
        },
    ]
