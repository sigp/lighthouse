# HTTP API

[OpenAPI Specification](https://ethereum.github.io/beacon-APIs/)

## Beacon Node

A Lighthouse beacon node can be configured to expose a HTTP server by supplying the `--http` flag. The default listen address is `localhost:5052`.

The following CLI flags control the HTTP server:

- `--http`: enable the HTTP server (required even if the following flags are
	provided).
- `--http-port`: specify the listen port of the server.
- `--http-address`: specify the listen address of the server.

The schema of the API aligns with the standard Eth2 Beacon Node API as defined
at [github.com/ethereum/beacon-APIs](https://github.com/ethereum/beacon-APIs).
It is an easy-to-use RESTful HTTP/JSON API.  An interactive specification is
available [here](https://ethereum.github.io/beacon-APIs/).

## Troubleshooting

### HTTP API is unavailable or refusing connections

Ensure the `--http` flag has been supplied at the CLI.

You can quickly check that the HTTP endpoint is up using `curl`:

```
curl "localhost:5052/beacon/head"

{"slot":37934,"block_root":"0x4d3ae7ebe8c6ef042db05958ec76e8f7be9d412a67a0defa6420a677249afdc7","state_root":"0x1c86b13ffc70a41e410eccce20d33f1fe59d148585ea27c2afb4060f75fe6be2","finalized_slot":37856,"finalized_block_root":"0xbdae152b62acef1e5c332697567d2b89e358628790b8273729096da670b23e86","justified_slot":37888,"justified_block_root":"0x01c2f516a407d8fdda23cad4ed4381e4ab8913d638f935a2fe9bd00d6ced5ec4","previous_justified_slot":37856,"previous_justified_block_root":"0xbdae152b62acef1e5c332697567d2b89e358628790b8273729096da670b23e86"}
```
