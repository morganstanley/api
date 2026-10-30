# Python WebSocket Client Example Project
This project is a starting template for integrating with WebSocket APIs on the API Platform.
It uses the following libraries: 
- [Microsoft's `msal` library](https://github.com/AzureAD/microsoft-authentication-library-for-python) for getting access tokens from Azure AD
- The [`websocket-client` library](https://github.com/websocket-client/websocket-client/tree/master) to handle WebSocket connections

It requires some simple security configuration to enable you to authenticate to the platform.

## Requirements
- Python 3.11+ (uv can install this for you, see below)
- A client application on Morgan Stanley Azure AD tenant. Please talk to your contact at Morgan Stanley to set this up.
- A self-signed public/private key pair. Please see the Morgan Stanley API Onboarding instructions for help generating these.
- The thumbprint (also known as fingerprint) for your certificate. 
  - You can retrieve this from your certificate using OpenSSL with the following command: `openssl x509 -noout -fingerprint -in cert.cer`

## Configuration
Create a file, config.json, with the following properties:
| Key                  | Description                                                                             |
|----------------------|-----------------------------------------------------------------------------------------|
| `client_id`          | The client id that will be sent to you from your Morgan Stanley contact                 |
| `scopes`             | The scope/s that will be sent to you from your Morgan Stanley contact                   |
| `thumbprint`         | The certificate thumbprint                                                              |
| `private_key_file`   | The path to the private_key.pem that has been created                                   |
| `tenant`             | The tenant that will be sent to you from your Morgan Stanley contact                    |
| `url`                | The URL of the Morgan Stanley API endpoint you are connecting to                        |

### Optional `config.json` Properties

| Key                     | Description                                                                                          | Example Value                        |
|-------------------------|------------------------------------------------------------------------------------------------------|--------------------------------------|
| `proxy_host`            | Hostname of your proxy server (if inside a restricted network)                                       | `"internal-proxy.company.com"`       |
| `proxy_port`            | Port number for your proxy (integer)                                                                 | `8080`                               |
| `requests_ca_bundle`    | Path to CA bundle file for HTTPS certificate verification. If omitted, uses default from `requests`. | `"/path/to/ca-bundle.pem"`           |
| `disable_ssl_verification` | Set to `true` to disable SSL verification (**not recommended for security reasons**).             | `false` or `true`                    |
| `retry_bad_handshake_status` | Whether or not to retry if the downstream API returns a handshake status other than 101 Switching Protocols. This may indicate an outage on the API and you may not always want to retry in this situation. Default value is `true`. | `true` or `false` |

You may use [`config-example.json`](./config-example.json) as a starting point.

> NOTE: You may recieve a Thumbprint in the formal 12:AB:FC:12, please remove the ":" so the thumbrpint would be 12ABFC12

By default trace logging is enabled, to show the WebSocket handshake and messages in transit. 
If you want to reduce the amount of logs output, please remove this line from the beginning of `client.py`:

```python
websocket.enableTrace(True)
```

## Running the application
This project uses [uv](https://docs.astral.sh/uv/) to manage Python, the virtual environment and dependencies.
Dependencies are declared in `pyproject.toml` and pinned in `uv.lock`.

### With uv (recommended)
Install uv by following the [installation guide](https://docs.astral.sh/uv/getting-started/installation/), then from this directory run:

```bash
uv sync
uv run client.py
```

`uv sync` will download a suitable Python version if needed, create a `.venv` virtual environment and install the exact versions from `uv.lock`, including the dev dependencies.

### Without uv
If you would rather not use uv, you can install from `pyproject.toml` with pip.
You will need Python 3.11 or greater and pip 25.1 or greater (for `--group` support). Check your Python version with `python --version` (on Mac/Linux, use `python3` if this shows Python 2).
If Python is not installed, you can download it from <https://www.python.org/downloads/>.

Note that pip does not read `uv.lock`: the direct dependencies are pinned in `pyproject.toml`, but their sub-dependencies may resolve to different versions than CI uses.

Windows:
```cmd
python -m venv .venv
.\.venv\Scripts\activate

python -m pip install --upgrade pip
pip install . --group dev

python client.py
```

Mac/Linux:
```bash
python -m venv .venv
. .venv/bin/activate

python -m pip install --upgrade pip
pip install . --group dev

python client.py
```

The application will launch and connect to the Morgan Stanley API offering and output the result.

## Testing
The tests have been built using the `unittest` framework, but can be run using the `pytest` command.
```bash
uv run pytest tests
```

If you are not using uv, run `pytest tests` from inside the activated virtual environment.

## Linting
This project uses `black` to lint its source code for readability. To lint the code please run the following:

```bash
uv run black .
```

If you are not using uv, run `black .` from inside the activated virtual environment.

# Manual testing of WebSocket APIs with wscat
An alternative to this script is to test your application using a command-line tool. `cURL` is intended for regular HTTP requests, and is not recommended for testing WebSockets.
One utility you can use instead is [`wscat`](https://github.com/websockets/wscat). Please see the `wscat` docs for full reference on the available options.

## Installation
`wscat` is available on NPM.

```bash
npm install -g wscat
```

Once you have an access token (please see the relevant section of the client setup guide) you can call a WebSocket API as follows.
Note that this example sets `$ACCESS_TOKEN`, `$PROXY_HOST` and `$PROXY_PORT` as environment variables beforehand.

```bash
wscat -H "Authorization: Bearer $ACCESS_TOKN" --proxy "http://$PROXY_HOST:$PROXY_PORT" -c wss://api.morganstanley.com/websocket-api
```

## SSL Validation issues and the `requests` CA bundle
Some organisations use an internal network separated from the Internet at large by a secure proxy. 
This requires the use of custom SSL certificates to ensure that the identity of websites can be verified.

If your client application is running behind a proxy, you may see the following error when trying to run the app:

```log
requests.exceptions.SSLError: HTTPSConnectionPool(host='[HOST]', port=443): Max retries exceeded with url: [OPENID URL HERE] (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate in certificate chain (_ssl.c:1007)')))
```

You have two options here:
- Disable SSL certificate verification. This is **not recommended** for security reasons, but may be useful as a test. You can do this by setting `disable_ssl_verification` to `true` in `config.json`
- Configure your program to use the system certificates.

Please see the next two sections for instructions to fix this problem on both Windows and Linux.
You may wish to engage the support of an engineering team at your organisation if you have trouble here, because the exact configuration will vary based on the system in use.

### Windows
On Windows, this problem can be solved by installing an additional library called `pip_system_certs`. 
You can find the homepage for this library at <https://pypi.org/project/pip-system-certs/>.

After installing the other dependencies as explained in the [Running the application](#running-the-application) section:

```cmd
uv add pip_system_certs
```

Or, if you are not using uv, run `pip install pip_system_certs` from inside the activated virtual environment.

### Linux 

On Linux, the solution for this problem is to set the CA bundle `requests` will use when establishing connections to the standard system bundle.
This should be available on your in a predictable location and is used by your browser, etc. 
The location varies by platform; some pointers for commonly-used operating systems are below:

| OS | Standard location |
| --- | ---- |
| Ubuntu | `/etc/ssl/certs` |
| CentOS or RedHat Enterprise Linux |  `/etc/pki/ca-trust` |
| Fedora | `/etc/pki/ca-trust` |
| Generic Linux | `/etc/ssl/certs` | 
| Windows | N/A - see previous section |

You are looking for a bundle file in `.pem` format; sometimes the directory will have the bundle in different formats. 
You should then set the `requests_ca_bundle` property in `config.json`. 

For example:

```json
{
  //... etc
  "url": "URL HERE",
  "requests_ca_bundle": "/etc/ssl/certs/pem/ca-bundle.pem"
}
```

# Legal

Morgan Stanley makes this available to you under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. 
See the NOTICE file distributed with this work for additional information regarding copyright ownership.
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and limitations under the License.