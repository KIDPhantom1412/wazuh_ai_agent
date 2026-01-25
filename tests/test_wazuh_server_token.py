import re
import time

import pytest


@pytest.fixture(autouse=True)
def reset_global_state():
    from wazuh_api import wazuh_server_token as token_module

    token_module._cached_token = None
    token_module._token_obtained_time = None

    yield

    token_module._cached_token = None
    token_module._token_obtained_time = None


def test_wazuh_server_token_first_request(requests_mock):
    from wazuh_api.wazuh_server_token import wazuh_server_token

    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "test_token_123"}},
        status_code=200,
    )

    token = wazuh_server_token()
    assert token == "test_token_123"
    assert requests_mock.called
    assert requests_mock.call_count == 1


def test_wazuh_server_token_uses_cache(requests_mock):
    from wazuh_api.wazuh_server_token import wazuh_server_token

    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "test_token_456"}},
        status_code=200,
    )

    token1 = wazuh_server_token()
    assert token1 == "test_token_456"
    assert requests_mock.call_count == 1

    token2 = wazuh_server_token()
    assert token2 == "test_token_456"
    assert requests_mock.call_count == 1


def test_wazuh_server_token_expired(requests_mock):
    from wazuh_api.wazuh_server_token import wazuh_server_token

    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "test_token_789"}},
        status_code=200,
    )

    token1 = wazuh_server_token()
    assert token1 == "test_token_789"
    assert requests_mock.call_count == 1

    wazuh_server_token.__globals__["_token_obtained_time"] = time.time() - 1000

    token2 = wazuh_server_token()
    assert token2 == "test_token_789"
    assert requests_mock.call_count == 2
