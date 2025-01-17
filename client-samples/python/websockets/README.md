# Python WebSocket Client Example Project
This project is a starting template for integrating with WebSocket APIs on the API Platform.
It uses the following libraries: 
- [Microsoft's `msal` library](https://github.com/AzureAD/microsoft-authentication-library-for-python) for getting access tokens from Azure AD
- The [`websocket-client` library](https://github.com/websocket-client/websocket-client/tree/master) to handle WebSocket connections


## Requirements
- Python 3.9+
- A client application on Morgan Stanley Azure AD tenant. Please talk to your contact at Morgan Stanley to set this up.
- A self-signed public/private key pair. Please see the Morgan Stanley API Onboarding instructions for help generating these.
- The thumbprint (also known as fingerprint) for your certificate. 
  - You can retrieve this from your certificate using OpenSSL with the following command: `openssl x509 -noout -fingerprint -in cert.cer`

## Installation
```bash
# create a virtual environment in the 'virtualenv' folder
# NOTE: this is optional but recommended
python -m venv venv

source virtualenv/bin/activate # on Linux, using bash
.\venv\Scripts\activate # on Windows

python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration
Create a file, config.json, with the following properties:
 - `client_id`: Your Client Id for the Morgan Stanley API Platform. This is a GUID.
 - `scopes`: A list of scopes to request a token against, corresponding to the API you are calling. For help with finding the correct scope, please talk to your Morgan Stanley contact.
 - `thumbprint`: The thumbprint (also known as fingerprint) of your certificate, without colon separators. For example `AB48C0D31F95EBF8425AECF3E7E6FA92B34C8D47`
 - `private_key_file`: The path to your private key. This can be either an absolute or relative path. For example: `websockets/private_key.pem`
 - `tenant`: The tenant you are requesting an access token against. 
   - UAT: `api-uat.morganstanley.com`
   - PROD : `api.morganstanley.com`
 - `proxy_host`: If you are running this app inside a restricted network environment, you should specify the hostname of the proxy you are using. e.g. `internal-proxy.company.com`
 - `proxy_port`: Set this to the port number for your proxy, if applicable. Should be an integer.
 - `url`: The WebSocket URL to call. **NOTE** in a production app you probably won't source the URL like this, but this is just an example.
 - `requests_ca_bundle`: The file to use as the CA bundle when verifying HTTPS certificates. If omitted, use the default bundle shipped with the `requests` library. Please see the [SSL validation section](#ssl-validation-issues-and-the-requests-ca-bundle) for more details.
 - `disable_ssl_verification`: Explicitly disable SSL verification. **Not recommended for security reasons.**
 - `retry_bad_handshake_status`: Whether or not to retry if the downstream API returns a handshake status other than 101 Switching Protocols. This may indicate an outage on the API and you may not always want to retry in this situation. Default value is `true`.

You may use [`config-example.json`](./config-example.json) as a starting point.

> NOTE: You may recieve a Thumbprint in the formal 12:AB:FC:12, please remove the ":" so the thumbrpint would be 12ABFC12

By default trace logging is enabled, to show the WebSocket handshake and messages in transit. 
If you want to reduce the amount of logs output, please remove this line from the beginning of `client.py`:

```python
websocket.enableTrace(True)
```

## Testing
The tests have been built using the `unittest` framework, but can be run using the `pytest` command.
```bash
pytest tests
```

## Linting
This project uses `black` to lint its source code for readability. To lint the code please run the following:

```bash
black .
```

## Running the app
```bash
python client.py
```

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

After installing the other dependencies as explained in the Installation section:

```cmd
pip install pip_system_certs
```

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