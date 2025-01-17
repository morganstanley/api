# Python REST Client Example Project
This project is a starting template for integrating with REST APIs on the API Platform.
It uses the following libraries: 
- [Microsoft's `msal` library](https://github.com/AzureAD/microsoft-authentication-library-for-python) for getting access tokens from Azure AD
- The [`requests` library](https://pypi.org/project/requests/) to send HTTP requests

It requires some simple security configuration to enable you to authenticate to the platform.

## Requirements
- Python 3.8+
- A client application on Morgan Stanley Azure AD tenant. Please talk to your contact at Morgan Stanley to set this up.
- A self-signed public/private key pair. Please see the client setup guide for instructions to generate this.
- The thumbprint (also known as fingerprint) for your certificate. 
  - You can retrieve this from your cert using OpenSSL with the following command: `openssl x509 -noout -fingerprint -in cert.cer`

## Configuration
Create a file, config.json, with the following properties:
 - `client_id`: Your Client Id for the Morgan Stanley API Platform. This is a GUID.
 - `scopes`: A list of scopes to request a token against, corresponding to the API you are calling. For help with finding the correct scope, please talk to your Morgan Stanley contact.
 - `thumbprint`: The thumbprint (also known as fingerprint) of your certificate, without colon separators. For example `AB48C0D31F95EBF8425AECF3E7E6FA92B34C8D47`
 - `private_key_file`: The path to your private key. This can be either an absolute or relative path. For example: `certs/private_key.pem`
 - `tenant`: The tenant you are requesting an access token against. 
   - UAT: `api-uat.morganstanley.com`
   - PROD : `api.morganstanley.com`
 - `proxy_host`: If you are running this app inside a restricted network environment, you should specify the hostname of the proxy you are using. e.g. `internal-proxy.company.com`
 - `proxy_port`: Set this to the port number for your proxy, if applicable. Should be an integer.
 - `url`: The URL to call. **NOTE** in a production app you probably won't source the URL like this, but this is just an example.
 - `requests_ca_bundle`: The file to use as the CA bundle when verifying HTTPS certificates. If omitted, use the default bundle shipped with the `requests` library. Please see the [SSL validation section](#ssl-validation-issues-and-the-requests-ca-bundle) for more details.
 - `disable_ssl_verification`: Explicitly disable SSL verification. **Not recommended for security reasons.**

You can use `config-example.json` as a starting point.

> NOTE: You may recieve a Thumbprint in the format 12:AB:FC:12. Please remove the ":" characters, the thumbrpint should look like 12ABFC12

## Running the application
It is important to ensure that you have Python 3.9 or greater on your machine. To check if Python is on your machine perform the following:

* Windows: `python --version`
* Mac/Linux: `python --version`

If the command is not recognised then you will need to install Python on your machine. 
This can be done by visiting <https://www.python.org/downloads/> where you can follow the instructions to download and install python.

Once Python is installed you can run following to launch the application. Please refer to the docs for current best practice on creating a virtual env https://docs.python.org/3/tutorial/venv.html:

Windows:    
```cmd
python -m venv venv
.\venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt

python client-application.py
```

Mac/Linux:   
```bash
python -m venv venv
. venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
python client-application.py
```

The application will launch and connect to the Morgan Stanley API offering and output the result.

## Testing
The tests have been built using the `unittest` framework, but can be run using the `pytest` command.
```bash
pytest tests
```

## Linting
This project uses `black` to lint its source code for readability. 
To lint the code from inside the virtual env please run the following:

```bash
black .
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