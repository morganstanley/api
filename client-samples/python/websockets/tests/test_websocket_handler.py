import asyncio
import threading
import time
from unittest.mock import MagicMock

import pytest
from websockets.asyncio.server import serve

import client
from client import create_connection

MOCK_TOKEN = "mock_token"

API_HOST = "localhost"
API_PORT = 8765
API_URL = f"ws://{API_HOST}:{API_PORT}"


async def on_connect(websocket):
    await websocket.send("Connected")
    await asyncio.sleep(2)
    await websocket.close()


async def run_server():
    async with serve(on_connect, API_HOST, API_PORT) as server:
        await server.serve_forever()


@pytest.fixture
def websocket_server():
    """
    Start a local WebSocket server that sends one message to each client.
    The thread is a daemon, so it stops when the test run ends.
    """
    server_thread = threading.Thread(
        target=lambda: asyncio.run(run_server()), daemon=True
    )
    server_thread.start()
    time.sleep(1)
    return API_URL


@pytest.fixture(autouse=True)
def mock_auth(monkeypatch):
    """
    Skip Azure AD: replace the MSAL client app and the token request with stubs.
    """
    monkeypatch.setattr(client, "acquire_token", lambda app, scopes: MOCK_TOKEN)
    monkeypatch.setattr(client, "get_client_app", lambda config: None)
    monkeypatch.setattr(client, "get_requests_ca_bundle", lambda config: None)


def test_websocket_handler_connects_and_receives_message(mock_config, websocket_server):
    """
    Connect to a local WebSocket server, and test the handler can connect and receive messages.
    """
    mock_config["proxy_host"] = None
    mock_config["proxy_port"] = None

    websocket_handler = create_connection(mock_config, websocket_server)
    websocket_handler.on_open = MagicMock()
    websocket_handler.on_message = MagicMock()

    thread = threading.Thread(target=websocket_handler.connect, kwargs={"retry": False})
    thread.start()
    thread.join(timeout=5)

    if thread.is_alive():
        pytest.fail("websocket_handler.connect() took longer than 5 seconds to run")

    websocket_handler.on_open.assert_called_once()
    websocket_handler.on_message.assert_called_once()
