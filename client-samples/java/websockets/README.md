# Java Websocket Client Example Project
This project is a starting template for integrating with Websocket APIs on the API Platform.

## How to use this template
The first step is to create the DER encoded file and configure the properties file, as described below.

The rest of the websocket logic lays in the [WebSocketService](./src/main/java/com/ms/infra/example/application/websocket/WebSocketService.java) class. This is where you should implement your onMessage logic.

### Create DER Encoded File
For this example the RSA Private key that was generated, `private_key.pem`, is not in a format that Java will understand and needs to be converted to a binary encoding.
The [PKCS8](https://en.wikipedia.org/wiki/PKCS_8) format is a standardized way to store a private key information.
To convert the `private_key.pem` to PKCS8 use the following command

```shell
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
```
The `der` output format is just an encoding format, to find out more check <https://en.wikipedia.org/wiki/X.690#DER_encoding>

Now that we have the private key file in a usable format we can use the Java Client to test the connection to Morgan Stanley's API offering.

### Properties
Make these changes to the `META-INF/microprofile-config.properties` resource file

| Property Name                     | Description                                                                             | Required |
|-----------------------------------|-----------------------------------------------------------------------------------------|----------|
| `morgan-stanley-oauth2-token-uri` | Morgan Stanley OAuth2 token endpoint URL                                                | True     |
| `client-app-id`                   | The client id that will be sent to you from your Morgan Stanley contact                 | True     |
| `client-app-scope`                | The scope/s that will be sent to from your Morgan Stanley contact                       | True     |
| `private-key-file`                | The path to the private_key.der that has been created                                   | True     |
| `public-certificate-file`         | The path to the public_key.cer that was created and sent to your Morgan Stanley contact | True     |
| `api-url`                         | Morgan Stanley API url                                                                  | True     | 
| `proxy-host`                      | Optional proxy host                                                                     | False    |
| `proxy-port`                      | Optional proxy port                                                                     | False    |

## Running the Java Client application
This template is designed and tested on the following Java LTS versions:
- 11
- 17
- 21


It is important to ensure that the Java SDK is installed and the `JAVA_HOME` environment variable has been set.
This can be checked by performing the following:

* Windows cmd: `echo %JAVA_HOME%`
* Mac/Linux terminal: `echo $JAVA_HOME`

If the result is empty, you will need to download and configure Java on your machine.

Once the Java SDK is installed and the `JAVA_HOME` environment variable has been set it is possible to run the application.
Type in the appropriate command to launch the application

* Windows: `gradlew.bat bootRun`
* Mac/Linux: `./gradlew bootRun`

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
wscat -H "Authorization: Bearer $ACCESS_TOKEN" --proxy "http://$PROXY_HOST:$PROXY_PORT" -c wss://api.morganstanley.com/websocket-api
```

# Legal

Morgan Stanley makes this available to you under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
See the NOTICE file distributed with this work for additional information regarding copyright ownership.
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.