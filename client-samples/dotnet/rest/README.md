# .NET Rest Client Example Project
This project is a starting template for integrating with REST APIs on the API Platform.

It requires some simple security configuration to enable you to authenticate to the platform.

## Requirements
- .NET 10.0.x
- A client application on Morgan Stanley Azure AD tenant. Please talk to your contact at Morgan Stanley to set this up.
- A self-signed public/private key pair. Please see the client setup guide for instructions to generate this.

## Configuration
Set the following values in the ClientCredentials section in [appsettings.json](./api-template/appsettings.json).

| Property Name        | Description                                                                             |
|----------------------|-----------------------------------------------------------------------------------------|
| `ClientId`           | The client id that will be sent to you from your Morgan Stanley contact                 |
| `PrivateKeyFile`     | The path to the private_key.pem that has been created                                   |
| `PublicKeyFile`      | The path to the public_key.cer that was created and sent to your Morgan Stanley contact |
| `Scopes`             | The scope/s that will be sent to you from your Morgan Stanley contact                   |
| `Tenant`             | The tenant that will be sent to you from your Morgan Stanley contact                    |
| `Url`                | The URL of the Morgan Stanley API endpoint you are connecting to                        |

### Proxies
If you would like to route your API call through a Proxy, then add the `ProxySettings` section to [appsettings.json](./api-template/appsettings.json). For example:

```json
{
  "ClientCredentials": {
    "ClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    ...
  },
  "ProxySettings": {
    "ProxyHost": "proxy-host",
    "ProxyPort": "8080"
  }
}
```

### Running the Application
Restore dependencies:

```shell
dotnet restore api-template
dotnet restore api-template.tests
```

Run the application:

```shell
dotnet run --project api-template
```

Build the application:

```shell
dotnet build api-template
```

### Testing the Application

Run unit tests:

```shell
dotnet test api-template.tests
```

# Legal

Morgan Stanley makes this available to you under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. 
See the NOTICE file distributed with this work for additional information regarding copyright ownership.
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and limitations under the License.
