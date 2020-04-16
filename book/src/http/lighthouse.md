# Lighthouse REST API: `/lighthouse`

The `/lighthouse` endpoints provide lighthouse-specific information about the beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/lighthouse/syncing`](#lighthousesyncing) | Get the node's syncing status

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
