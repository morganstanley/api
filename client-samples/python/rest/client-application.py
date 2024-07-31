# Morgan Stanley makes this available to you under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. 
# See the NOTICE file distributed with this work for additional information regarding copyright ownership.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and limitations under the License.

from msal import ConfidentialClientApplication
import sys
import json
import logging
import requests
import time
from typing import List

# uncomment this line for DEBUG level logging in case of errors
# logging.basicConfig(level=logging.DEBUG)

def load_config(config_file: str):
    """
    Load the config map from a JSON file with the given path.

    Parameters
    ----------
    config_file: str
        The path to the config file to load.
    """
    with open(config_file, mode="r") as f:
        return json.load(f)


def load_private_key(private_key_file: str):
    """
    Load the private key from a PEM file with the given path.

    Parameters
    ----------
    private_key_file: str
        The path to the private key to load.
    """
    with open(private_key_file, mode="r") as f:
        return f.read()


def get_proxies(config: dict) -> dict | None:
    """
    Returns proxy config from the config dictionary if the correct config has been provided.
    Otherwise returns None.

    Parameters
    ----------
    config: dict
        The config map to use.
    """
    proxy_host = config.get("proxy_host")
    proxy_port = config.get("proxy_port")
    proxies = None
    if proxy_host is not None:
        if proxy_port is None:
            raise Exception("Missing proxy port.")
        proxies = {
            "http": f"{proxy_host}:{proxy_port}",
            "https": f"{proxy_host}:{proxy_port}",
        }
    return proxies


def get_requests_ca_bundle(config: dict) -> str | bool:
    """
    Get the system CA bundle, if it's set. This is only necessary if your environment uses a proxy, since the bundled certificates will not work.
    This returns True if no CA bundle is set; this tells requests to use the default, bundled certificates.

    Parameters
    ----------
    config: dict
        The config map to use.

    Returns
    -------
    If SSL has been explicitly disabled: False
    If SSL is enabled and should use the default settings: False
    If a custom SSL bundle will be used: a string with an absolute path to a .pem file on the system. The config map to use.
    """

    if config.get("disable_ssl_verification"):
        return False
    return config.get("requests_ca_bundle") or True


def get_client_app(config: dict):
    """
    Configures an MSAL client application, that can later be used to request an access token.

    Parameters
    ----------
    config: dict
        The config map to use.
    """
    client_id = config["client_id"]
    thumbprint = config["thumbprint"]
    private_key_path = config["private_key_file"]
    authority = f"https://login.microsoftonline.com/{config['tenant']}"
    proxies = get_proxies(config)

    private_key = load_private_key(private_key_path)

    requests_ca_bundle = get_requests_ca_bundle(config)

    return ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential={"thumbprint": thumbprint, "private_key": private_key},
        proxies=proxies,
        verify=requests_ca_bundle
    )


def acquire_token(app: ConfidentialClientApplication, scopes: List[str]):
    """
    Gets an access token against the provided scopes using a pre-configured MSAL app.

    Parameters
    ----------
    app: ConfidentialClientApplication
        The preconfigured MSAL ConfidentialClientApplication to request a token with.
    scopes: List[str]
        The list of scopes to request a token against.
    """

    result = app.acquire_token_silent(scopes, account=None)

    if not result:
        print(
            "No suitable token exists in cache. Retrieving a new token from Azure AD."
        )
        result = app.acquire_token_for_client(scopes=scopes)

    if "access_token" not in result:
        print("Expected an access token in response. Instead, got the following:")
        print(result)
        raise Exception("Bad response from Azure AD")

    return result["access_token"]


if __name__ == "__main__":
    print("Starting Client application")
    config = load_config("config.json")

    app = get_client_app(config)
    access_token = acquire_token(app, config["scopes"])

    proxies = get_proxies(config)
    url = config["url"]

    requests_ca_bundle = get_requests_ca_bundle(config)

    print("Calling API.")
    # Call API using the access token
    response = requests.get(  # Use token to call downstream service
        url, 
        headers={"Authorization": "Bearer " + access_token}, 
        proxies=proxies,
        verify=requests_ca_bundle
    ).json()

    print("API call result: %s" % json.dumps(response, indent=2))
