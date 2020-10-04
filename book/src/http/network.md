# Lighthouse REST API: `/network`

The `/network` endpoints provide information about the p2p network that
Lighthouse uses to communicate with other beacon nodes.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/network/enr`](#networkenr) | Get the local node's `ENR` as base64 .
[`/network/peer_count`](#networkpeer_count) | Get the count of connected peers.
[`/network/peer_id`](#networkpeer_id) | Get a node's libp2p `PeerId`.
[`/network/peers`](#networkpeers) | List a node's connected peers (as `PeerIds`).
[`/network/listen_port`](#networklisten_port) | Get a node's libp2p listening port.
[`/network/listen_addresses`](#networklisten_addresses) | Get a list of libp2p multiaddr the node is listening on.

## `network/enr`

Requests the beacon node for its listening `ENR` address.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/enr`
Method | GET
JSON Encoding | String (base64)
Query Parameters | None
Typical Responses | 200

### Example Response

```json
"-IW4QPYyGkXJSuJ2Eji8b-m4PTNrW4YMdBsNOBrYAdCk8NLMJcddAiQlpcv6G_hdNjiLACOPTkqTBhUjnC0wtIIhyQkEgmlwhKwqAPqDdGNwgiMog3VkcIIjKIlzZWNwMjU2azGhA1sBKo0yCfw4Z_jbggwflNfftjwKACu-a-CoFAQHJnrm"
```

## `/network/peer_count`

Requests the count of peers connected to the client.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/peer_count`
Method | GET
JSON Encoding | Number
Query Parameters | None
Typical Responses | 200

### Example Response

```json
5
```
## `/network/peer_id`

Requests the beacon node's local `PeerId`.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/peer_id`
Method | GET
JSON Encoding | String (base58)
Query Parameters | None
Typical Responses | 200

### Example Response

```json
"QmVFcULBYZecPdCKgGmpEYDqJLqvMecfhJadVBtB371Avd"
```

## `/network/peers`

Requests one `MultiAddr` for each peer connected to the beacon node.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/peers`
Method | GET
JSON Encoding | [String] (base58)
Query Parameters | None
Typical Responses | 200

### Example Response

```json
[
	"QmaPGeXcfKFMU13d8VgbnnpeTxcvoFoD9bUpnRGMUJ1L9w",
	"QmZt47cP8V96MgiS35WzHKpPbKVBMqr1eoBNTLhQPqpP3m"
]
```


## `/network/listen_port`

Requests the TCP port that the client's libp2p service is listening on.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/listen_port`
Method | GET
JSON Encoding | Number
Query Parameters | None
Typical Responses | 200

### Example Response

```json
9000
```

## `/network/listen_addresses`

Requests the list of multiaddr that the client's libp2p service is listening on.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/network/listen_addresses`
Method | GET
JSON Encoding | Array
Query Parameters | None
Typical Responses | 200

### Example Response

```json
[
    "/ip4/127.0.0.1/tcp/9000",
    "/ip4/192.168.31.115/tcp/9000",
    "/ip4/172.24.0.1/tcp/9000",
    "/ip4/172.21.0.1/tcp/9000",
    "/ip4/172.17.0.1/tcp/9000",
    "/ip4/172.18.0.1/tcp/9000",
    "/ip4/172.19.0.1/tcp/9000",
    "/ip4/172.42.0.1/tcp/9000",
    "/ip6/::1/tcp/9000"
]
```
