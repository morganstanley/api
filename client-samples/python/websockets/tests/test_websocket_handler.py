import os
import sys
import asyncio
import threading
from time import sleep
import unittest
from unittest.mock import MagicMock, patch

from websockets.asyncio.server import serve

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from test_consts import MOCK_CONFIG
from client import create_connection

LOCAL_MOCK_CONFIG = MOCK_CONFIG.copy()
LOCAL_MOCK_CONFIG["proxy_host"] = None
LOCAL_MOCK_CONFIG["proxy_port"] = None

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


def start_echo_server():
    asyncio.run(run_server())


class TestApiCall(unittest.TestCase):
    def setUp(self):
        """
        setUp function runs before each unit test.
        Sets up patches
        """
        self.acquire_token_patch = patch(
            "client.acquire_token", return_value=MOCK_TOKEN
        )
        self.get_client_app_patch = patch("client.get_client_app", return_value=None)
        self.get_requests_ca_bundle_patch = patch(
            "client.get_requests_ca_bundle", return_value=None
        )
        self.acquire_token_patch.start()
        self.get_client_app_patch.start()
        self.get_requests_ca_bundle_patch.start()

    def tearDown(self):
        """
        tearDown function runs after each unit test.
        """
        self.acquire_token_patch.stop()
        self.get_client_app_patch.stop()
        self.get_requests_ca_bundle_patch.stop()

    def connect(self):
        self.websocket_handler.connect(retry=False)

    def test_websocket_handler_connects_and_receives_messgae(self):
        """
        Connect to a websockets echo server, and test websocket handler can connect and recieve messages.
        """
        # As the thread is set as a daemon, the code will exit, once main thread is done.
        server_thread = threading.Thread(target=start_echo_server, daemon=True)
        server_thread.start()
        sleep(1)

        self.websocket_handler = create_connection(LOCAL_MOCK_CONFIG, API_URL)
        self.websocket_handler.on_open = MagicMock()
        self.websocket_handler.on_message = MagicMock()

        thread = threading.Thread(target=self.connect)
        thread.start()
        thread.join(timeout=5)

        # If thread is still alive after 5 seconds, fail the test
        if thread.is_alive():
            self.fail("websocket_handler.connect() took longer than 5 seconds to run")

        self.websocket_handler.on_open.assert_called_once()
        self.websocket_handler.on_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
