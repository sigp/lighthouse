# Beacon Node API

Lighthouse implements the standard [Beacon Node API
specification][OpenAPI]. Please follow that link for a full description of each API endpoint.

## Starting the server

A Lighthouse beacon node can be configured to expose an HTTP server by supplying the `--http` flag. The default listen address is `http://127.0.0.1:5052`.

The following CLI flags control the HTTP server:

- `--http`: enable the HTTP server (required even if the following flags are
	provided).
- `--http-port`: specify the listen port of the server.
- `--http-address`: specify the listen address of the server. It is _not_ recommended to listen
  on `0.0.0.0`, please see [Security](#security) below.
- `--http-allow-origin`: specify the value of the `Access-Control-Allow-Origin`
	header. The default is to not supply a header.
- `--http-enable-tls`: serve the HTTP server over TLS. Must be used with `--http-tls-cert`
	and `http-tls-key`. This feature is currently experimental, please see
	[Serving the HTTP API over TLS](#serving-the-http-api-over-tls) below.
- `--http-tls-cert`: specify the path to the certificate file for Lighthouse to use.
- `--http-tls-key`: specify the path to the private key file for Lighthouse to use.

The schema of the API aligns with the standard Beacon Node API as defined
at [github.com/ethereum/beacon-APIs](https://github.com/ethereum/beacon-APIs).
An interactive specification is available [here][OpenAPI].

## Security

**Do not** expose the beacon node API to the public internet or you will open your node to
denial-of-service (DoS) attacks.

The API includes several endpoints which can be used to trigger heavy processing, and as
such it is strongly recommended to restrict how it is accessed. Using `--http-address` to change
the listening address from `localhost` should only be done with extreme care.

To safely provide access to the API from a different machine you should use one of the following
standard techniques:

* Use an [SSH tunnel][ssh_tunnel], i.e. access `localhost` remotely. This is recommended, and
  doesn't require setting `--http-address`.
* Use a firewall to limit access to certain remote IPs, e.g. allow access only from one other
  machine on the local network.
* Shield Lighthouse behind an HTTP server with rate-limiting such as NGINX. This is only
  recommended for advanced users, e.g. beacon node hosting providers.

Additional risks to be aware of include:

* The `node/identity` and `node/peers` endpoints expose information about your node's peer-to-peer
  identity.
* The `--http-allow-origin` flag changes the server's CORS policy, allowing cross-site requests
  from browsers. You should only supply it if you understand the risks, e.g. malicious websites
  accessing your beacon node if you use the same machine for staking and web browsing.

## CLI Example

Start a beacon node and an execution node according to [Run a node](./run_a_node.md). Note that since [The Merge](https://ethereum.org/en/roadmap/merge/), an execution client is required to be running along with a beacon node. Hence, the query on Beacon Node APIs requires users to run both. While there are some Beacon Node APIs that you can query with only the beacon node, such as the [node version](https://ethereum.github.io/beacon-APIs/#/Node/getNodeVersion), in general an execution client is required to get the updated information about the beacon chain, such as [state root](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateRoot), [headers](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders) and many others, which are dynamically progressing with time.


## HTTP Request/Response Examples

This section contains some simple examples of using the HTTP API via `curl`.
All endpoints are documented in the [Beacon Node API
specification][OpenAPI].

### View the head of the beacon chain

Returns the block header at the head of the canonical chain.

```bash
curl -X GET "http://localhost:5052/eth/v1/beacon/headers/head" -H  "accept: application/json" | jq
```

```json
{
  "execution_optimistic": false,
  "finalized": false,
  "data": {
    "root": "0x9059bbed6b8891e0ba2f656dbff93fc40f8c7b2b7af8fea9df83cfce5ee5e3d8",
    "canonical": true,
    "header": {
      "message": {
        "slot": "6271829",
        "proposer_index": "114398",
        "parent_root": "0x1d2b4fa8247f754a7a86d36e1d0283a5e425491c431533716764880a7611d225",
        "state_root": "0x2b48adea290712f56b517658dde2da5d36ee01c41aebe7af62b7873b366de245",
        "body_root": "0x6fa74c995ce6f397fa293666cde054d6a9741f7ec280c640bee51220b4641e2d"
      },
      "signature": "0x8258e64fea426033676a0045c50543978bf173114ba94822b12188e23cbc8d8e89e0b5c628a881bf3075d325bc11341105a4e3f9332ac031d89a93b422525b79e99325928a5262f17dfa6cc3ddf84ca2466fcad86a3c168af0d045f79ef52036"
    }
  }
}
```

The `jq` tool is used to format the JSON data properly. If it returns `jq: command not found`, then you can install `jq` with `sudo apt install -y jq`. After that, run the command again, and it should return the head state of the beacon chain.

### View the status of a validator

Shows the status of validator at index `1` at the `head` state.

```bash
curl -X GET "http://localhost:5052/eth/v1/beacon/states/head/validators/1" -H  "accept: application/json"
```

```json
{
  "execution_optimistic": false,
  "finalized": false,
  "data": {
    "index": "1",
    "balance": "32004587169",
    "status": "active_ongoing",
    "validator": {
      "pubkey": "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c",
      "withdrawal_credentials": "0x01000000000000000000000015f4b914a0ccd14333d850ff311d6dafbfbaa32b",
      "effective_balance": "32000000000",
      "slashed": false,
      "activation_eligibility_epoch": "0",
      "activation_epoch": "0",
      "exit_epoch": "18446744073709551615",
      "withdrawable_epoch": "18446744073709551615"
    }
  }
}
```
You can replace `1` in the above command with the validator index that you would like to query. Other API query can be done similarly by changing the link according to the Beacon API.

## Serving the HTTP API over TLS
> **Warning**: This feature is currently experimental.

The HTTP server can be served over TLS by using the `--http-enable-tls`,
`http-tls-cert` and `http-tls-key` flags.
This allows the API to be accessed via HTTPS, encrypting traffic to
and from the server.

This is particularly useful when connecting validator clients to
beacon nodes on different machines or remote servers.
However, even when serving the HTTP API server over TLS, it should
not be exposed publicly without one of the security measures suggested
in the [Security](#security) section.

Below is a simple example serving the HTTP API over TLS using a
self-signed certificate on Linux:

### Enabling TLS on a beacon node
Generate a self-signed certificate using `openssl`:
```bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```
Note that currently Lighthouse only accepts keys that are not password protected.
This means we need to run with the `-nodes` flag (short for 'no DES').

Once generated, we can run Lighthouse and an execution node according to [Run a node](./run_a_node.md). In addition, add the flags `--http-enable-tls --http-tls-cert cert.pem --http-tls-key key.pem` to Lighthouse, the command should look like:

```bash
lighthouse bn \
  --network mainnet \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --http \
  --http-enable-tls \
  --http-tls-cert cert.pem \
  --http-tls-key key.pem
```
Note that the user running Lighthouse must have permission to read the
certificate and key.

The API is now being served at `https://localhost:5052`.

To test connectivity, you can run the following:
```bash
curl -X GET "https://localhost:5052/eth/v1/node/version" -H  "accept: application/json" --cacert cert.pem | jq

```
### Connecting a validator client
In order to connect a validator client to a beacon node over TLS, the validator
client needs to be aware of the certificate.
There are two ways to do this:
#### Option 1: Add the certificate to the operating system trust store
The process for this will vary depending on your operating system.
Below are the instructions for Ubuntu and Arch Linux:

```bash
# Ubuntu
sudo cp cert.pem /usr/local/share/ca-certificates/beacon.crt
sudo update-ca-certificates
```

```bash
# Arch
sudo cp cert.pem /etc/ca-certificates/trust-source/anchors/beacon.crt
sudo trust extract-compat
```

Now the validator client can be connected to the beacon node by running:
```bash
lighthouse vc --beacon-nodes https://localhost:5052
```

#### Option 2: Specify the certificate via CLI
You can also specify any custom certificates via the validator client CLI like
so:
```bash
lighthouse vc --beacon-nodes https://localhost:5052 --beacon-nodes-tls-certs cert.pem
```

## Troubleshooting

### HTTP API is unavailable or refusing connections

Ensure the `--http` flag has been supplied at the CLI.

You can quickly check that the HTTP endpoint is up using `curl`:

```bash
curl -X GET "http://localhost:5052/eth/v1/node/version" -H  "accept:application/json"
```

The beacon node should respond with its version:

```json
{"data":{"version":"Lighthouse/v4.1.0-693886b/x86_64-linux"}
```

If this doesn't work, the server might not be started or there might be a
network connection error.

### I cannot query my node from a web browser (e.g., Swagger)

By default, the API does not provide an `Access-Control-Allow-Origin` header,
which causes browsers to reject responses with a CORS error.

The `--http-allow-origin` flag can be used to add a wild-card CORS header:

```bash
lighthouse bn --http --http-allow-origin "*"
```

> **Warning:** Adding the wild-card allow-origin flag can pose a security risk.
> Only use it in production if you understand the risks of a loose CORS policy.

[OpenAPI]: https://ethereum.github.io/beacon-APIs/
[ssh_tunnel]: https://www.ssh.com/academy/ssh/tunneling/example
