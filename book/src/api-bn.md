# Beacon Node API

Lighthouse implements the standard [Eth2 Beacon Node API
specification][OpenAPI]. Please follow that link for a full description of each API endpoint.

## Starting the server

A Lighthouse beacon node can be configured to expose a HTTP server by supplying the `--http` flag. The default listen address is `127.0.0.1:5052`.

The following CLI flags control the HTTP server:

- `--http`: enable the HTTP server (required even if the following flags are
	provided).
- `--http-port`: specify the listen port of the server.
- `--http-address`: specify the listen address of the server. It is _not_ recommended to listen
     on `0.0.0.0`, please see [Security](#security) below.
- `--http-allow-origin`: specify the value of the `Access-Control-Allow-Origin`
		header. The default is to not supply a header.

The schema of the API aligns with the standard Eth2 Beacon Node API as defined
at [github.com/ethereum/eth2.0-APIs](https://github.com/ethereum/eth2.0-APIs).
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

Start the beacon node with the HTTP server listening on [http://localhost:5052](http://localhost:5052):

```bash
lighthouse bn --http
```

## HTTP Request/Response Examples

This section contains some simple examples of using the HTTP API via `curl`.
All endpoints are documented in the [Eth2 Beacon Node API
specification][OpenAPI].

### View the head of the beacon chain

Returns the block header at the head of the canonical chain.

```bash
curl -X GET "http://localhost:5052/eth/v1/beacon/headers/head" -H  "accept:
application/json"
```

```json
{
  "data": {
    "root": "0x4381454174fc28c7095077e959dcab407ae5717b5dca447e74c340c1b743d7b2",
    "canonical": true,
    "header": {
      "message": {
        "slot": "3199",
        "proposer_index": "19077",
        "parent_root": "0xf1934973041c5896d0d608e52847c3cd9a5f809c59c64e76f6020e3d7cd0c7cd",
        "state_root": "0xe8e468f9f5961655dde91968f66480868dab8d4147de9498111df2b7e4e6fe60",
        "body_root": "0x6f183abc6c4e97f832900b00d4e08d4373bfdc819055d76b0f4ff850f559b883"
      },
      "signature": "0x988064a2f9cf13fe3aae051a3d85f6a4bca5a8ff6196f2f504e32f1203b549d5f86a39c6509f7113678880701b1881b50925a0417c1c88a750c8da7cd302dda5aabae4b941e3104d0cf19f5043c4f22a7d75d0d50dad5dbdaf6991381dc159ab"
    }
  }
}
```

### View the status of a validator

Shows the status of validator at index `1` at the `head` state.

```bash
curl -X GET "http://localhost:5052/eth/v1/beacon/states/head/validators/1" -H  "accept: application/json"
```

```json
{
  "data": {
    "index": "1",
    "balance": "63985937939",
    "status": "Active",
    "validator": {
      "pubkey": "0x873e73ee8b3e4fcf1d2fb0f1036ba996ac9910b5b348f6438b5f8ef50857d4da9075d0218a9d1b99a9eae235a39703e1",
      "withdrawal_credentials": "0x00b8cdcf79ba7e74300a07e9d8f8121dd0d8dd11dcfd6d3f2807c45b426ac968",
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

## Troubleshooting

### HTTP API is unavailable or refusing connections

Ensure the `--http` flag has been supplied at the CLI.

You can quickly check that the HTTP endpoint is up using `curl`:

```bash
curl -X GET "http://localhost:5052/eth/v1/node/version" -H  "accept: application/json"
```

The beacon node should respond with its version:

```json
{"data":{"version":"Lighthouse/v0.2.9-6f7b4768a/x86_64-linux"}}
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

[OpenAPI]: https://ethereum.github.io/eth2.0-APIs/#/
[ssh_tunnel]: https://www.ssh.com/academy/ssh/tunneling/example
