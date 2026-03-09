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

def get_agents_summary():
    """Get summary of agents."""
    logger.info("Getting agents summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary", headers=requests_headers, verify=False
    )
    logger.info("Get agents summary successfully")
    return response.json()

def list_agents(pretty: bool = False):
    """List all agents."""
    logger.info("Listing all agents")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents?pretty={pretty}",
        headers=requests_headers,
        verify=False,
    )
    logger.info("List all agents successfully")
    return response.json()

def get_agents_os_summary():
    """Get summary of agents operating systems."""
    logger.info("Getting agents OS summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary/os",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agents OS summary successfully")
    return response.json()

def get_agents_overview():
    """Get overview of agents."""
    logger.info("Getting agents overview")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/overview/agents",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agents overview successfully")
    return response.json()

def get_rule_info(rule_id: int):
    """Get information about a specific rule by its ID."""
    logger.info(f"Getting rule information for rule ID: {rule_id}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/rules?rule_ids={rule_id}",
        headers=requests_headers,
        verify=False,
    )
    logger.info(f"Get rule information for rule ID {rule_id} successfully")
    return response.json()

def get_config_agentless():
    """Get agentless configuration."""
    logger.info("Getting agentless configuration")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/configuration?section=agentless",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agentless configuration successfully")
    return response.json()


if __name__ == "__main__":
    # print(get_wazuh_server_api_info())
    print(get_agents_status_summary())
    print(get_agents_os_summary())
    print(list_agents(True))
    print(get_agents_summary())
    print(get_agents_overview())

    print(get_config_agentless())
