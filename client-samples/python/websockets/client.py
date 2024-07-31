# Morgan Stanley makes this available to you under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. 
# See the NOTICE file distributed with this work for additional information regarding copyright ownership.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and limitations under the License.

from msal import ConfidentialClientApplication
from typing import List, Optional
import socket
import sys
import json
import time
import websocket
import ssl

# remove this to reduce the volume of logs generated
websocket.enableTrace(True)

# uncomment this line for DEBUG level logging in case of errors getting access tokens
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


def get_requests_ca_bundle(config: dict) -> str | bool:
    """
    Get the system CA bundle, if it's set. This is only necessary if your environment uses a proxy, since the bundled certificates will not work.
    This returns True if no CA bundle is set; this tells requests to use the default, bundled certificates.
    If "disable_ssl_verification" is set to true this explicitly disables SSL verification.

    Parameters
    ----------
    config: dict
        The config map to use.

    Returns
    -------
    If SSL has been explicitly disabled: False
    If SSL is enabled and should use the default settings: False
    If a custom SSL bundle will be used: a string with an absolute path to a .pem file on the system.
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
    requests_ca_bundle = get_requests_ca_bundle(config)
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

    private_key = load_private_key(private_key_path)

    return ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential={"thumbprint": thumbprint, "private_key": private_key},
        proxies=proxies,
        verify=requests_ca_bundle,
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


def get_sslopts(verify_http: bool | str):
    """
    Constructs an SSLOpts object to use when establishing a WebSocket connection.
    """
    if not verify_http:
        # explicitly disable
        print("\n\nWARNING: explicitly disabling SSL verification for WebSocket connection! By using this feature, your connection is not secure! \n")
        return {"cert_reqs": ssl.CERT_NONE}
    if verify_http == True:
        # None = default settings
        return None

    # construct an SSL context pointing at system CA certs.
    capath = verify_http

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(capath)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    return {'context': context}


class WebSocketHandler:
    """
    Handler class to wrap the base websocket client and also handle auth and automatic reconnections.
    """

    def __init__(
        self,
        url: str,
        client_app: ConfidentialClientApplication,
        scopes: List[str],
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        verify_http: bool | str = True,
    ):
        """
        WebSocketHandler initialisation

        Parameters
        ----------
        url: str
            WebSocket URL to connect to.
        client_app: ConfidentialClientApplication
            An MSAL ConfidentialClientApplication configured to get access tokens from Azure AD. Use get_client_app() to get this.
        scopes: List[str]
            The scopes to request an access token against.
        proxy_host: Optional[str]
            The hostname of the proxy to use. Should be a hostname only without a scheme or port - e.g. "proxy.website.com"
        proxy_port: Optional[int]
            The port number of the proxy to use.
        verify_http: bool
            Whether to verify the SSL certificate for the WebSocket connection. Should be turned on in production for increased security.
        """

        self.opened = False
        self.client_app = client_app
        self.url = url
        self.scopes = scopes
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.verify_http = verify_http

    def connect(self):
        # instantiate new app to ensure old connection is properly cleaned up
        self.ws = websocket.WebSocketApp(
            self.url,
            header={},
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
        )

        # NOTE: providing a function as the header parameter means it will be called on every connection, ensuring access token is refreshed.
        def get_headers():
            print("Getting an access token before connection")
            token = acquire_token(self.client_app, self.scopes)
            return {"Authorization": f"Bearer {token}"}

        self.ws.header = get_headers
        print("Opening WebSocket connection")

        # set the proxy if required
        proxy_host_ip = None
        if self.proxy_host is not None:
            if self.proxy_port is None:
                raise Exception("Missing proxy port.")
            # websocket-client requires the proxy as an IP address, not a hostname
            proxy_host_ip = socket.gethostbyname(self.proxy_host)
            print("Resolved IP", proxy_host_ip, "from proxy host", self.proxy_host)
        proxy_type = "http" if self.proxy_host is not None else None

        ssl_options = get_sslopts(self.verify_http)

        # try to reconnect forever; disconnect handler will exit the app if needed
        while True:
            self.ws.run_forever(
                http_proxy_host=proxy_host_ip,
                http_proxy_port=self.proxy_port,
                proxy_type=proxy_type,
                sslopt=ssl_options,
                reconnect=False
            )
            
    def on_message(self, ws, message):
        # put your logic here or pass the message out using a callback
        print("Received message: ", message)


    def on_error(self, ws, error):
        print("An error occurred. Type of error: " + str(type(error)))
        print("Error message: " + str(error))

        if isinstance(error, KeyboardInterrupt):
            print("User terminated app, exiting")
            sys.exit(1)

        if isinstance(error, websocket.WebSocketBadStatusException):
            print("Bad handshake status, not retrying")
            sys.exit(1)

        print("Trying to reconnect")
        # loop will retry


    def on_close(self, ws, close_status_code, close_msg):
        print("Connection was closed")

    def on_open(self, ws):
        print("Opened connection")


def create_connection(config: dict, url: str):
    scopes = config["scopes"]
    print("Getting an access token")
    proxy_host = config.get("proxy_host")
    proxy_port = config.get("proxy_port")
    requests_ca_bundle = get_requests_ca_bundle(config)
    app = get_client_app(config)

    return WebSocketHandler(
        url=url,
        client_app=app,
        scopes=scopes,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        verify_http=requests_ca_bundle,
    )


def run():
    config = load_config("config.json")
    url = config["url"]  # just an example, use whatever logic you want here
    handler = create_connection(config, url)
    print("Opening connection")
    handler.connect()


if __name__ == "__main__":
    run()
