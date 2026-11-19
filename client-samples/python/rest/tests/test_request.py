import pytest

import client_application
from client_application import call_api

MOCK_TOKEN = "MOCK_TOKEN"
MOCK_BODY_RESPONSE = {"status": "success", "response": "Hello World!"}


@pytest.fixture(autouse=True)
def mock_auth(monkeypatch):
    """
    Skip Azure AD: replace the MSAL client app and the token request with stubs.
    """
    monkeypatch.setattr(client_application, "get_client_app", lambda config: None)
    monkeypatch.setattr(
        client_application, "acquire_token", lambda app, scopes: MOCK_TOKEN
    )


@pytest.mark.parametrize(
    "status_code, json",
    [
        (200, MOCK_BODY_RESPONSE),
        (401, {}),
        (404, {}),
        (500, {}),
    ],
)
def test_call_api(mock_config, requests_mock, status_code: int, json: dict):
    """
    Mock calling the API with different responses.
    """
    mock_request = requests_mock.get(
        mock_config["url"], status_code=status_code, json=json
    )

    response = call_api(mock_config)

    assert response.status_code == status_code
    assert response.json() == json
    assert mock_request.last_request.headers["Authorization"] == f"Bearer {MOCK_TOKEN}"
