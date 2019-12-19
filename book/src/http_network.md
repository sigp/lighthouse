# Lighthouse REST API: `/network`

The `/network` endpoints provide information about the p2p network that
Lighthouse uses to communicate with other beacon nodes.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/network/peer_id`](#networkpeer_id) | Get a node's libp2p `PeerId`.
[`/network/peers`](#networkpeers) | List a node's libp2p peers (as `PeerIds`).
[`/network/enr`](#networkenr) | Get a node's discovery `ENR` address.

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
