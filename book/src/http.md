# HTTP API

[![Swagger Badge]][Swagger Link]

[Swagger Badge]: https://img.shields.io/badge/Open%20API-0.2.0-success
[Swagger Link]: https://app.swaggerhub.com/apis-docs/spble/lighthouse_rest_api/0.2.0


**The Lighthouse API is documented in Open API format and is available at
[SwaggerHub: Lighthouse REST
API](https://app.swaggerhub.com/apis-docs/spble/lighthouse_rest_api/0.2.0).**

By default, a Lighthouse `beacon_node` exposes a HTTP server on `localhost:5052`.

The following CLI flags control the HTTP server:

- `--no-api`: disable the HTTP server.
- `--api-port`: specify the listen port of the server.
- `--api-address`: specify the listen address of the server.

## Examples

In addition to the complete Open API docs (see above), some examples are
provided below.

_Examples assume there is a Lighthouse node exposing a HTTP API on
`localhost:5052`. Responses are JSON._

### Get the node's beacon chain head

```bash
$ curl localhost:5052/beacon/head

{"slot":0,"block_root":"0x827bf71805540aa13f6d8c7d18b41b287b2094a4d7a28cbb8deb061dbf5df4f5","state_root":"0x90a78d73294bc9c7519a64e1912161be0e823eb472012ff54204e15a4d717fa5"}%
```

### Get the node's finalized checkpoint

```bash
$ curl localhost:5052/beacon/latest_finalized_checkpoint

{"epoch":0,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"}%
```

### Get the node's ENR

```bash
$ curl localhost:5052/network/enr

"-IW4QFyf1VlY5pZs0xZuvKMRZ9_cdl9WMCDAAJXZiZiuGcfRYoU40VPrYDLQj5prneJIz3zcbTjHp9BbThc-yiymJO8HgmlwhH8AAAGDdGNwgiMog3VkcIIjKIlzZWNwMjU2azGhAjg0-DsTkQynhJCRnLLttBK1RS78lmUkLa-wgzAi-Ob5"%
```

### Get a list of connected peer ids

```bash
$ curl localhost:5052/network/peers

["QmeMFRTWfo3KbVG7dEBXGhyRMa29yfmnJBXW84rKuGEhuL"]%
```

### Get the node's peer id

```bash
$ curl localhost:5052/network/peer_id

"QmRD1qs2AqNNRdBcGHUGpUGkpih5cmdL32mhh22Sy79xsJ"%
```

### Get the list of listening libp2p addresses

Lists all the libp2p multiaddrs that the node is listening on.

```bash
$ curl localhost:5052/network/listen_addresses

["/ip4/127.0.0.1/tcp/9000","/ip4/192.168.1.121/tcp/9000","/ip4/172.17.0.1/tcp/9000","/ip4/172.42.0.1/tcp/9000","/ip6/::1/tcp/9000","/ip6/fdd3:c293:1bc::203/tcp/9000","/ip6/fdd3:c293:1bc:0:9aa9:b2ea:c610:44db/tcp/9000"]%
```

### Pretty-print the genesis state and state root

Returns the genesis state and state root in your terminal, in YAML.

```bash
$ curl --header "Content-Type: application/yaml" "localhost:5052/beacon/state?slot=0"
```
