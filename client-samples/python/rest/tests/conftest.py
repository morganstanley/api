from pathlib import Path

import pytest

TEST_CONFIG_FILE = Path(__file__).parent / "test-config.json"


@pytest.fixture
def mock_config() -> dict:
    """The config in test-config.json, as a dict each test can safely modify."""
    return {
        "client_id": "CLIENT-ID",
        "scopes": ["API-SCOPE"],
        "thumbprint": "CERT-THUMBPRINT",
        "private_key_file": "PRIVATE-KEY-PATH",
        "tenant": "TENANT",
        "proxy_host": "PROXY-HOST",
        "proxy_port": "PROXY-PORT",
        "url": "HTTP://URL/",
    }
