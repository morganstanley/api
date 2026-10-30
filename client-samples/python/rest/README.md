# Python REST Client Example Project
This project is a starting template for integrating with REST APIs on the API Platform.
It uses the following libraries: 
- [Microsoft's `msal` library](https://github.com/AzureAD/microsoft-authentication-library-for-python) for getting access tokens from Azure AD
- The [`requests` library](https://pypi.org/project/requests/) to send HTTP requests

It requires some simple security configuration to enable you to authenticate to the platform.

## Requirements
- Python 3.11+ (uv can install this for you, see below)
- A client application on Morgan Stanley Azure AD tenant. Please talk to your contact at Morgan Stanley to set this up.
- A self-signed public/private key pair. Please see the client setup guide for instructions to generate this.
- The thumbprint (also known as fingerprint) for your certificate. 
  - You can retrieve this from your cert using OpenSSL with the following command: `openssl x509 -noout -fingerprint -in cert.cer`

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

See [SSL validation section](#ssl-validation-issues-and-the-requests-ca-bundle) for more details.

You can use `config-example.json` as a starting point.

> NOTE: You may recieve a Thumbprint in the format 12:AB:FC:12. Please remove the ":" characters, the thumbrpint should look like 12ABFC12

## Running the application
This project uses [uv](https://docs.astral.sh/uv/) to manage Python, the virtual environment and dependencies.
Dependencies are declared in `pyproject.toml` and pinned in `uv.lock`.

### With uv (recommended)
Install uv by following the [installation guide](https://docs.astral.sh/uv/getting-started/installation/), then from this directory run:

```bash
uv sync
uv run client_application.py
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

python client_application.py
```

Mac/Linux:
```bash
python -m venv .venv
. .venv/bin/activate

python -m pip install --upgrade pip
pip install . --group dev

python client_application.py
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