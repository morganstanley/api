import sys
import os
import unittest
from unittest.mock import patch
import requests_mock
from parameterized import parameterized

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client_application import call_api
from test_consts import MOCK_CONFIG

URL = "HTTP://URL"
MOCK_TOKEN = "MOCK_TOKEN"
MOCK_BODY_RESPONSE = {"status": "success", "response": "Hello World!"}


class TestApiCall(unittest.TestCase):
    def setUp(self):
        """
        setUp function runs before each unit test.
        Parameters
        ----------
        acquire_token: Mock
            Mock return for the acquire_token method.
        get_client_app_mock: Mock
            Mock return for the get_client_app method.
        """
        # create patches of the acquire_token and get_client_app methods
        self.acquire_token_patch = patch(
            "client_application.acquire_token", return_value=MOCK_TOKEN
        )
        self.get_client_app_patch = patch(
            "client_application.get_client_app", return_value=None
        )

        # Start the patches
        self.acquire_token_patch.start()
        self.get_client_app_patch.start()

    def tearDown(self):
        """
        tearDown function runs after each unit test.
        """
        self.acquire_token_patch.stop()
        self.get_client_app_patch.stop()
        return super().tearDown()

    @parameterized.expand(
        [
            [200, MOCK_BODY_RESPONSE],
            [401, {}],
            [404, {}],
            [500, {}],
        ]
    )
    @requests_mock.Mocker()
    def test_call_api(
        self, status_code: int, json: dict, mock_request: requests_mock.Mocker
    ):
        """
        Mock calling API with different responses.
        Parameters
        ----------
        status_code: int
            Status code for the response.
        json: dict
            JSON response for the response.
        mock_request: requests_mock.Mocker
            Mock return for the requests get function.
        """
        mock_request.get(URL, status_code=status_code, json=json)

        response = call_api(MOCK_CONFIG)
        self.assertEqual(response.status_code, status_code)
        self.assertEqual(response.json(), json)


if __name__ == "__main__":
    unittest.main()
