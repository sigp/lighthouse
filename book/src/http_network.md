# Lighthouse REST API: `/network`

## Endpoints

Table of endpoints:

HTTP Path | Description |
| --- | -- |
[`/network/peer_id`](#network-peerid) | Get a node's libp2p `PeerId`.
[`/network/peers`](#network-peers) | List a node's libp2p peers (as `PeerIds`).
[`/network/enr`](#network-enr-address) | Get a node's discovery `ENR` address.

## Network Peer ID

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

## Network Peers

Requests the beacon node for one `MultiAddr` for each connected peer.

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

## Network ENR Address

Requests the beacon node for it's listening `ENR` address.

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
