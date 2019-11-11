# Websocket API

By default, a Lighthouse `beacon_node` exposes a websocket server on `localhost:5053`.

The following CLI flags control the websocket server:

- `--no-ws`: disable the websocket server.
- `--ws-port`: specify the listen port of the server.
- `--ws-address`: specify the listen address of the server.

All clients connected to the websocket server will receive the same stream of events, all triggered
by the `BeaconChain`. Each event is a JSON object with the following schema:

```json
{
    "event": "string",
    "data": "object"
}
```

## Events

The following events may be emitted:

### Beacon Head Changed

Occurs whenever the canonical head of the beacon chain changes.

```json
{
    "event": "beacon_head_changed",
    "data": {
        "reorg": "boolean",
        "current_head_beacon_block_root": "string",
        "previous_head_beacon_block_root": "string"
    }
}
```

### Beacon Finalization

Occurs whenever the finalized checkpoint of the canonical head changes.

```json
{
    "event": "beacon_finalization",
    "data": {
        "epoch": "number",
        "root": "string"
    }
}
```

### Beacon Block Imported

Occurs whenever the beacon node imports a valid block.

```json
{
    "event": "beacon_block_imported",
    "data": {
        "block": "object"
    }
}
```

### Beacon Block Rejected

Occurs whenever the beacon node rejects a block because it is invalid or an
error occurred during validation.

```json
{
    "event": "beacon_block_rejected",
    "data": {
        "reason": "string",
        "block": "object"
    }
}
```

### Beacon Attestation Imported

Occurs whenever the beacon node imports a valid attestation.

```json
{
    "event": "beacon_attestation_imported",
    "data": {
        "attestation": "object"
    }
}
```

### Beacon Attestation Rejected

Occurs whenever the beacon node rejects an attestation because it is invalid or
an error occurred during validation.

```json
{
    "event": "beacon_attestation_rejected",
    "data": {
        "reason": "string",
        "attestation": "object"
    }
}
```
