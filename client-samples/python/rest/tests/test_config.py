from client_application import get_proxies, load_config
from conftest import TEST_CONFIG_FILE


def test_config(mock_config):
    """
    Test that the correct config is loaded.
    """
    assert load_config(TEST_CONFIG_FILE) == mock_config


def test_proxies(mock_config):
    """
    Test that the correct proxies are loaded.
    """
    assert get_proxies(mock_config) == {
        "http": "PROXY-HOST:PROXY-PORT",
        "https": "PROXY-HOST:PROXY-PORT",
    }


def test_null_proxy_config(mock_config):
    """
    Test that no proxies are loaded when the proxy_host and proxy_port are not provided.
    """
    del mock_config["proxy_host"]
    del mock_config["proxy_port"]

    assert get_proxies(mock_config) is None
