from datetime import UTC, datetime, timedelta

import requests
import urllib3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Wazuh Topology API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_wazuh_url() -> str:
    return (
        f"{settings.WAZUH_SERVER_API_PROTOCOL}://"
        f"{settings.WAZUH_SERVER_API_HOST}:{settings.WAZUH_SERVER_API_PORT}"
    )


def get_indexer_url() -> str:
    return (
        f"{settings.WAZUH_SERVER_API_PROTOCOL}://"
        f"{settings.WAZUH_SERVER_API_HOST}:{settings.WAZUH_INDEXER_PORT}"
    )


def get_wazuh_auth() -> tuple[str, str]:
    return (settings.WAZUH_SERVER_API_USERNAME, settings.WAZUH_SERVER_API_PASSWORD)


def get_indexer_auth() -> tuple[str, str]:
    return (settings.WAZUH_INDEXER_USER, settings.WAZUH_INDEXER_PASSWORD)


def get_wazuh_token() -> str:
    auth_url = f"{get_wazuh_url()}/security/user/authenticate"
    response = requests.get(auth_url, auth=get_wazuh_auth(), verify=False, timeout=30)
    response.raise_for_status()
    return response.json()["data"]["token"]


@app.get("/api/topo")
async def get_topology():
    try:
        token = get_wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}

        agents_response = requests.get(
            f"{get_wazuh_url()}/agents?limit=100",
            headers=headers,
            verify=False,
            timeout=30,
        )
        agents_response.raise_for_status()
        agents = agents_response.json()["data"]["affected_items"]

        time_start = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
        query_body = {
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 10}}},
                        {"range": {"timestamp": {"gte": time_start}}},
                    ]
                }
            },
        }
        alerts_response = requests.post(
            f"{get_indexer_url()}/wazuh-alerts-*/_search",
            json=query_body,
            auth=get_indexer_auth(),
            verify=False,
            timeout=30,
        )
        alerts_response.raise_for_status()
        alerts_hits = alerts_response.json().get("hits", {}).get("hits", [])

        alert_map = {}
        for hit in alerts_hits:
            alert = hit["_source"]
            agent_id = alert.get("agent", {}).get("id")
            if not agent_id:
                continue
            level = alert["rule"]["level"]
            if agent_id not in alert_map or level > alert_map[agent_id]["level"]:
                alert_map[agent_id] = {
                    "level": level,
                    "description": alert["rule"]["description"],
                }

        nodes = []
        for agent in agents:
            agent_id = agent["id"]
            threat = alert_map.get(agent_id)
            nodes.append(
                {
                    "id": agent_id,
                    "name": agent["name"],
                    "ip": agent.get("ip", "unknown"),
                    "status": agent["status"],
                    "has_threat": threat is not None,
                    "threat_info": threat["description"] if threat else "",
                    "threat_level": threat["level"] if threat else 0,
                }
            )

        return nodes
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502, detail=f"Failed to fetch topology data: {exc}"
        ) from exc


def main():
    import uvicorn

    uvicorn.run("service.topology_service:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    main()
