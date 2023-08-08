# For Protocol Developers

_Documentation for protocol developers._

This section lists Lighthouse-specific decisions that are not strictly spec'd and may be useful for
other protocol developers wishing to interact with lighthouse.


## Custom ENR Fields

Lighthouse currently uses the following ENR fields:

### Ethereum Consensus Specified

| Field | Description |
| ---- | ---- |
| `eth2` | The `ENRForkId` in SSZ bytes specifying which fork the node is on |
| `attnets` | An SSZ bitfield which indicates which of the 64 subnets the node is subscribed to for an extended period of time |
| `syncnets` | An SSZ bitfield which indicates which of the sync committee subnets the node is subscribed to |


### Lighthouse Custom Fields

Lighthouse is currently using the following custom ENR fields.
| Field | Description |
| ---- | ---- |
| `quic` | The UDP port on which the QUIC transport is listening on IPv4 |
| `quic6` | The UDP port on which the QUIC transport is listening on IPv6 |


## Custom RPC Messages

The specification leaves room for implementation-specific errors. Lighthouse uses the following
custom RPC error messages.

### Goodbye Reason Codes

| Code | Message | Description |
| ---- | ---- | ---- |
| 128 | Unable to Verify Network | Teku uses this, so we adopted it. It relates to having a fork mismatch |
| 129 | Too Many Peers | Lighthouse can close a connection because it has reached its peer-limit and pruned excess peers |
| 250 | Bad Score | The node has been dropped due to having a bad peer score |
| 251 | Banned | The peer has been banned and disconnected |
| 252 | Banned IP | The IP the node is connected to us with has been banned |


### Error Codes

| Code | Message | Description |
| ---- | ---- | ---- |
| 139 | Rate Limited | The peer has been rate limited so we return this error as a response |