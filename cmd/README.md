# securegrpc-gen

`securegrpc-gen` is a command-line tool within the `securegrpc` package that simplifies securing gRPC services by generating certificates and access control list (ACL) files for mutual TLS (mTLS) authentication and authorization.

## Introduction

The `securegrpc-gen` tool automates the creation of:
- A Certificate Authority (CA) certificate and key (optional).
- Server and client certificates signed by the CA for mTLS (selectively generated).
- An optional ACL rules file for fine-grained access control.

Designed for developers securing gRPC applications, it supports customizable key sizes, validity periods, multiple Subject Alternative Names (SANs), and selective generation of components.

## Installation

### Prerequisites
- **Go**: Version 1.16 or later (for module support). Install from [golang.org](https://golang.org/doc/install).

### Using `go install`
Install directly to your `$GOPATH/bin`:
```bash
go install github.com/r-scheele/securegrpc/cmd/securegrpc-gen@latest
securegrpc-gen --help
```


### Build from Source
Clone the repository and build:
```bash
go get github.com/r-scheele/securegrpc/cmd/securegrpc-gen
go build github.com/r-scheele/securegrpc/cmd/securegrpc-gen
./securegrpc-gen --help
```

This creates the `securegrpc-gen` binary in the current directory.


## Usage

Run the tool with:
```bash
securegrpc-gen --config <path/to/config.yaml> --out-dir <path/to/output>
```
- `--config`: Path to the YAML configuration file (required).
- `--out-dir`: Directory for generated files (optional, defaults to `.`).

## Configuration

The tool uses a YAML configuration file. Below is a full example showcasing all options:

```yaml
generate_ca: true
generate_server: true
generate_client: true

ca:
  country: "US"
  state: "California"
  locality: "San Francisco"
  organization: "Example Inc."
  common_name: "Example Root CA"
  key_size: 4096
  validity_days: 730

server:
  service_name: "my-server"
  ips:
    - "127.0.0.1"
    - "192.168.1.1"
  domains:
    - "localhost"
    - "server.example.com"
  ip: "127.0.0.1"  # Backward compatible, ignored if 'ips' is set
  domain: "localhost"  # Backward compatible, ignored if 'domains' is set
  key_size: 2048
  validity_days: 365
  key_usage: "digitalSignature,keyEncipherment,dataEncipherment"
  ext_key_usage: "serverAuth"

client:
  service_name: "my-client"
  key_size: 4096
  validity_days: 180
  key_usage: "digitalSignature"
  ext_key_usage: "clientAuth,emailProtection"

acl:
  generate: true
  output: "acl.json"
```

### Configuration Fields
- **`generate_ca`**: Boolean; set to `true` to generate the CA certificate and key.
- **`generate_server`**: Boolean; set to `true` to generate the server certificate and key.
- **`generate_client`**: Boolean; set to `true` to generate the client certificate and key.

- **`ca`**:
  - `country`, `state`, `locality`, `organization`, `common_name`: Subject fields for the CA.
  - `key_size`: RSA key size (default: 4096).
  - `validity_days`: Validity in days (default: 365).

- **`server`**:
  - `service_name`: Common Name (CN) for the server.
  - `ips`: List of IP addresses for SANs (new format).
  - `domains`: List of domain names for SANs (new format).
  - `ip`, `domain`: Single IP/domain (old format, backward compatible).
  - `key_size`, `validity_days`: As above.
  - `key_usage`: Comma-separated list (e.g., `digitalSignature,keyEncipherment`; default: `digitalSignature,keyEncipherment`).
  - `ext_key_usage`: Comma-separated list (e.g., `serverAuth`; default: `serverAuth`).

- **`client`**:
  - `service_name`: Common Name (CN) for the client.
  - `key_size`, `validity_days`, `key_usage`, `ext_key_usage`: As above (defaults: `digitalSignature`, `clientAuth`).

- **`acl`**:
  - `generate`: Boolean; set to `true` to generate the ACL file.
  - `output`: Filename for the ACL file.

## Generated Files

Depending on the config, the tool generates:
- **`ca.crt`, `ca.key`**: CA certificate and key (if `generate_ca: true`).
- **`server.crt`, `server.key`**: Server certificate and key (if `generate_server: true`).
- **`client.crt`, `client.key`**: Client certificate and key (if `generate_client: true`).
- **`<acl.output>`**: ACL rules file (if `acl.generate: true`).

### Notes
- If `generate_ca` is `false` but `generate_server` or `generate_client` is `true`, `ca.crt` and `ca.key` must exist in `--out-dir`.
- The ACL uses the `client.service_name` as the `ClientCN`.

## Dependencies

- **Go**: For building and running the tool.
- **`gopkg.in/yaml.v3`**: For parsing the YAML config (automatically fetched via Go modules).

## Examples

1. **Generate Everything**:
   ```bash
   securegrpc-gen --config config.yaml --out-dir certs
   ```
   With the full config above.

2. **Generate Only Client Certificate**:
   ```yaml
   generate_ca: false
   generate_server: false
   generate_client: true
   ca: {}
   server: {}
   client:
     service_name: "my-client"
     key_size: 4096
   acl:
     generate: false
   ```
   Ensure `ca.crt` and `ca.key` are in `certs/`.

3. **Generate Server Certificate, No ACL**:
   ```yaml
   generate_ca: false
   generate_server: true
   generate_client: false
   ca: {}
   server:
     service_name: "my-server"
     ips: ["127.0.0.1"]
     domains: ["localhost"]
   client: {}
   acl:
     generate: false
   ```
   Ensure `ca.crt` and `ca.key` are in `certs/`.

## Why Use securegrpc-gen?

- **mTLS Security**: Ensures mutual authentication between gRPC clients and servers.
- **Flexibility**: Supports selective generation, multiple SANs, and custom key/usage settings.
- **Portability**: No external dependencies, thanks to Go’s native crypto.
- **Ease of Use**: Streamlines certificate and ACL setup for gRPC services.

## Additional Resources

See the [securegrpc repository](https://github.com/r-scheele/securegrpc) for integration examples and the main library documentation.

