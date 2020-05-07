# Lighthouse REST API: `/lighthouse`

The `/lighthouse` endpoints provide lighthouse-specific information about the beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/lighthouse/syncing`](#lighthousesyncing) | Get the node's syncing status
[`/lighthouse/peers`](#lighthousepeers) | Get the peers info known by the beacon node
[`/lighthouse/connected_peers`](#lighthousepeers) | Get the connected_peers known by the beacon node

## `/lighthouse/syncing`

Requests the syncing state of a Lighthouse beacon node. Lighthouse as a
custom sync protocol, this request gets Lighthouse-specific sync information.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/syncing`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

If the node is undergoing a finalization sync:
```json
{
	"SyncingFinalized": {
		"start_slot": 10,
		"head_slot": 20,
		"head_root":"0x74020d0e3c3c02d2ea6279d5760f7d0dd376c4924beaaec4d5c0cefd1c0c4465"
	}
}
```

If the node is undergoing a head chain sync:
```json
{
	"SyncingHead": {
		"start_slot":0,
		"head_slot":1195
	}
}
```

If the node is synced
```json
{
"Synced"
}
```

## `/lighthouse/peers`

Get all known peers info from the beacon node.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/peers`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
[
{
      "peer_id" : "16Uiu2HAmTEinipUS3haxqucrn7d7SmCKx5XzAVbAZCiNW54ncynG",
      "peer_info" : {
         "_status" : "Healthy",
         "client" : {
            "agent_string" : "github.com/libp2p/go-libp2p",
            "kind" : "Prysm",
            "os_version" : "unknown",
            "protocol_version" : "ipfs/0.1.0",
            "version" : "unknown"
         },
         "connection_status" : {
            "Disconnected" : {
               "since" : 3
            }
         },
         "listening_addresses" : [
            "/ip4/10.3.58.241/tcp/9001",
            "/ip4/35.172.14.146/tcp/9001",
            "/ip4/35.172.14.146/tcp/9001"
         ],
         "meta_data" : {
            "attnets" : "0x0000000000000000",
            "seq_number" : 0
         },
         "reputation" : 20,
         "sync_status" : {
            "Synced" : {
               "status_head_slot" : 18146
            }
         }
      }
   },
   {
      "peer_id" : "16Uiu2HAm8XZfPv3YjktCjitSRtfS7UfHfEvpiUyHrdiX6uAD55xZ",
      "peer_info" : {
         "_status" : "Healthy",
         "client" : {
            "agent_string" : null,
            "kind" : "Unknown",
            "os_version" : "unknown",
            "protocol_version" : "unknown",
            "version" : "unknown"
         },
         "connection_status" : {
            "Disconnected" : {
               "since" : 5
            }
         },
         "listening_addresses" : [],
         "meta_data" : {
            "attnets" : "0x0900000000000000",
            "seq_number" : 0
         },
         "reputation" : 20,
         "sync_status" : "Unknown"
      }
   },
]
```

## `/lighthouse/connected_peers`

Get all known peers info from the beacon node.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/connected_peers`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
[
   {
      "peer_id" : "16Uiu2HAm8XZfPv3YjktCjitSRtfS7UfHfEvpiUyHrdiX6uAD55xZ",
      "peer_info" : {
         "_status" : "Healthy",
         "client" : {
            "agent_string" : null,
            "kind" : "Unknown",
            "os_version" : "unknown",
            "protocol_version" : "unknown",
            "version" : "unknown"
         },
         "connection_status" : {
            "Connected" : {
               "in" : 5,
			   "out" : 2
            }
         },
         "listening_addresses" : [],
         "meta_data" : {
            "attnets" : "0x0900000000000000",
            "seq_number" : 0
         },
         "reputation" : 20,
         "sync_status" : "Unknown"
      }
   },
   ]
```
