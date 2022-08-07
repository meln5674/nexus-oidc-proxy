# Nexus OIDC RBAC-Syncing Proxy

This server acts as a reverse proxy to add OIDC support to [Nexus](https://www.sonatype.com/products/nexus-repository). Nexus supports this directly by allowing a header to be set indicating the user ID to log in as, to be provided by a reverse proxy such as this one. A number of other open-source tools already do this, however, they only implement authentication, not authorization. This requires the administrator to manually manage the set of users, and their granted roles, manually, which defeats the purpose of single sign-on.

This server is different, and instead intergates with OIDC in a way that will feel familiar to anyone that has used [Harbor](https://goharbor.io/). This tool assumes another tool like [OAuth2-Proxy](https://oauth2-proxy.github.io/oauth2-proxy/docs/) is reverse proxying it to provide it the SSO access token, and then, tranlate that token into a Nexus API User object, and synchronize the Nexus user automatically on a configurable interval, as well as creating the user in the first place, in addition to reverse proxying each request. This allows for true integration with OIDC.

# This tool is still in early development, and experimental. Everything is subject to change. Use at your own risk.

## Building

Needed tools:

* Go 1.16+
* Docker (Or compatible OCI image builder tool) (if building docker image)
* Kubectl, Helm, Kind (For running integration tests)

```bash
# Executable
go build -o proxy main.go
# Docker image
docker build -t ${your_registry}/meln5674/nexus-oidc-proxy:$(git rev-parse HEAD)
docker push ${your_registry}/meln5674/nexus-oidc-proxy:$(git rev-parse HEAD)
```

## Configuration

Configuration is set through a configuration file for non-sentive information, and environment variables for sensitive information

### Configuration File

```yaml
http:
  # Address and port to listen on
  address: <listen address>:<listen port>
tls:
  # Set to true to serve using TLS (HTTPS)
  # Default false
  enabled: <true|false>
  # Path to your TLS certificate file
  certFile: </path/to/tls.crt>
  # Path to your TLS private key
  keyFile: </path/to/tls.key> 
nexus:
  # URL of the Upstream Nexus server
  upstream: http[s]://<nexus host>:<nexus port>[/<base path>]
  # The name of the header to set to the user ID in proxied requests 
  rutAuthHeader: <header name>
oidc:
  # How long to wait between synchronizing users/roles
  # See https://pkg.go.dev/time#ParseDuration for syntax
  syncInterval: <#(s|m|h|...)>
  # Name of the HTTP header to expect the downstream proxy to set to the JWT OIDC Access token 
  accessTokenHeader: <header name>
  # Golang template, see https://pkg.go.dev/text/template for xyntax 
  # Should produce a nexus user API object to onboard that user in YAML/JSON format
  # You will have access to Sprig functions (https://masterminds.github.io/sprig/)
  # You will have access to https://pkg.go.dev/github.com/golang-jwt/jwt/v4#Token as the .Token variable
  userTemplate: |-
    <template>
  # List of Golang templates, see https://pkg.go.dev/text/template for xyntax 
  # Each output should be a YAML list/JSON array of strings, each string being a valid nexus role name
  # You will have access to Sprig functions (https://masterminds.github.io/sprig/)
  # You will have access to https://pkg.go.dev/github.com/golang-jwt/jwt/v4#Token as the .Token variable
  # Outputs will be set unioned
  rolesTemplate:
  - |-
    <template>
  - ...
```

### Environment Variables

#### NEXUS_OIDC_PROXY_NEXUS_USERNAME

Username to use for onboarding and synchronizing users. 

#### NEXUS_OIDC_PROXY_NEXUS_PASSWORD

Password to use for onboarding and synchronizing users.

### Command Line Arguments

#### --config <path>

Specify path the configuration file described above

### Trusted Certificates

If your Nexus server uses a self-signed certificate or uses an internal CA, this application is written in Go and uses [the standard locations](https://go.dev/src/crypto/x509/root_linux.go) for finding CA Certificate Bundles. Add your self-signed certificate or internal CA to one of these bundles to have this server trust your Nexus server.

### Permissions

This application requires the following Nexus permissions to operate correctly:

* nx-users-create
* nx-users-read
* nx-users-update
* nx-userschangepw

### Nexus Setup

In addition to providing credentials, you must enable the Remote User Token (RUT) capability and Auth Realm. [See here](https://help.sonatype.com/repomanager3/nexus-repository-administration/user-authentication/authentication-via-remote-user-token#AuthenticationviaRemoteUserToken-ConfiguringNexusRepository) for instructions on doing this.

This tool only requires the OSS version of Nexus, it does not require any features from Pro or above.

### Deploying

It is recommended to deploy this tool containerized, in a Kubernetes Cluster. A Dockerfile and [Helm chart](./deploy/helm/nexus-oidc-proxy) are provided for doing so. See [here](./integration-test) for an example.

### Running Tests

```bash
./integration-test/run.sh
```
