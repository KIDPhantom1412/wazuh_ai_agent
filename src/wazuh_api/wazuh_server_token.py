import json
import logging
import time
from base64 import b64encode

import requests
import urllib3

from core.config import settings

protocol = settings.WAZUH_SERVER_API_PROTOCOL
host = settings.WAZUH_SERVER_API_HOST
port = settings.WAZUH_SERVER_API_PORT
user = settings.WAZUH_SERVER_API_USERNAME
password = settings.WAZUH_SERVER_API_PASSWORD
timeout = settings.WAZUH_SERVER_AUTH_TOKEN_EXP_TIMEOUT

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

login_endpoint = "security/user/authenticate"

login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
basic_auth = f"{user}:{password}".encode()
login_headers = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {b64encode(basic_auth).decode()}",
}

_cached_token = None
_token_obtained_time = None


def wazuh_server_token():
    global _cached_token, _token_obtained_time

    current_time = time.time()

    if _cached_token is not None and _token_obtained_time is not None:
        time_since_obtained = current_time - _token_obtained_time
        if time_since_obtained < timeout - 10:
            logger.debug(
                "Using cached token, time since obtained: %.2f seconds", time_since_obtained
            )
            return _cached_token

    logger.info("Token expired or not available, requesting new token...")
    response = requests.post(login_url, headers=login_headers, verify=False)
    response.raise_for_status()
    token_data = json.loads(response.content.decode())
    _cached_token = token_data["data"]["token"]
    _token_obtained_time = current_time
    logger.info("Successfully obtained new Wazuh token.")
    return _cached_token


if __name__ == "__main__":
    print(wazuh_server_token())
