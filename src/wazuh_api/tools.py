import logging

import requests

from core.config import settings
from wazuh_api.wazuh_server_token import wazuh_server_token

logger = logging.getLogger(__name__)

protocol = settings.WAZUH_SERVER_API_PROTOCOL
host = settings.WAZUH_SERVER_API_HOST
port = settings.WAZUH_SERVER_API_PORT

requests_headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {wazuh_server_token()}",
}


def get_wazuh_server_api_info():
    logger.info("Getting API information")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(f"{protocol}://{host}:{port}", headers=requests_headers, verify=False)
    logger.info("Get API information successfully")
    return response.json()


def get_agents_status_summary():
    logger.info("Getting agents status summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary/status", headers=requests_headers, verify=False
    )
    logger.info("Get agents status summary successfully")
    return response.json()


if __name__ == "__main__":
    print(get_wazuh_server_api_info())
    print(get_agents_status_summary())
