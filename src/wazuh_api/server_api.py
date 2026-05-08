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


def upload_rule_file(filename: str, content: str, overwrite: bool = False):
    """Upload a rule file to the Wazuh manager."""
    logger.info(f"Uploading rule file: {filename}")
    upload_headers = {
        "Authorization": f"Bearer {wazuh_server_token()}",
        "Content-Type": "application/octet-stream",
    }
    response = requests.put(
        f"{protocol}://{host}:{port}/rules/files/{filename}?overwrite={str(overwrite).lower()}",
        headers=upload_headers,
        data=content,
        verify=False,
    )
    if response.status_code == 200:
        logger.info(f"Upload rule file {filename} successfully")
    else:
        logger.error(f"Failed to upload rule file {filename}: {response.text}")
    return response.json()


def delete_rule_file(filename: str):
    """Delete a rule file from the Wazuh manager."""
    logger.info(f"Deleting rule file: {filename}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.delete(
        f"{protocol}://{host}:{port}/rules/files/{filename}",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info(f"Delete rule file {filename} successfully")
    else:
        logger.error(f"Failed to delete rule file {filename}: {response.text}")
    return response.json()


def restart_manager():
    """Restart the Wazuh manager."""
    logger.info("Restarting Wazuh manager")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.put(
        f"{protocol}://{host}:{port}/manager/restart",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Restart Wazuh manager successfully")
    else:
        logger.error(f"Failed to restart Wazuh manager: {response.text}")
    return response.json()


def validate_configuration():
    """Validate the Wazuh manager configuration."""
    logger.info("Validating Wazuh manager configuration")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/configuration/validation",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Validate configuration successfully")
    else:
        logger.error(f"Failed to validate configuration: {response.text}")
    return response.json()


def get_manager_logs(
    pretty: bool = False,
    limit: int | None = None,
    offset: int | None = None,
    tag: str | None = None,
    level: str | None = None,
):
    """Get Wazuh manager logs from ossec.log."""
    logger.info("Getting manager logs")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    params: dict[str, str | int | bool] = {"pretty": pretty}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if tag:
        params["tag"] = tag
    if level:
        params["level"] = level

    response = requests.get(
        f"{protocol}://{host}:{port}/manager/logs",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Get manager logs successfully")
    else:
        logger.error(f"Failed to get manager logs: {response.text}")
    return response.json()


def get_manager_logs_summary(pretty: bool = False):
    """Get summary of Wazuh manager logs."""
    logger.info("Getting manager logs summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/logs/summary",
        headers=requests_headers,
        params={"pretty": pretty},
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Get manager logs summary successfully")
    else:
        logger.error(f"Failed to get manager logs summary: {response.text}")
    return response.json()


def run_logtest(log_event: str, token: str = None, location: str = None, log_format: str = "json"):
    """Run logtest against a log event."""
    logger.info("Running logtest")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    payload = {"event": log_event, "log_format": log_format}
    if token:
        payload["token"] = token
    if location:
        payload["location"] = location

    response = requests.put(
        f"{protocol}://{host}:{port}/logtest",
        headers=requests_headers,
        json=payload,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Run logtest successfully")
    else:
        logger.error(f"Failed to run logtest: {response.text}")
    return response.json()


if __name__ == "__main__":
    print(get_wazuh_server_api_info())
    # print(get_agents_status_summary())
    # print(get_agents_os_summary())
    # print(list_agents(True))
    # print(get_agents_summary())
    # print(get_agents_overview())

    # print(get_config_agentless())
    # print(get_manager_logs(limit=20, tag="wazuh-analysisd"))
    # print(get_manager_logs_summary())
    print(get_rule_info(201))
    # print(validate_configuration())
