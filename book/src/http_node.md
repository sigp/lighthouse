# Lighthouse REST API: `/node`

The `/node` endpoints provide information about the lighthouse beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/node/version`](#nodeversion) | Get the node's version.
[`/node/syncing`](#nodesyncing) | Get the node's syncing status.
[`/node/syncing`](#nodelighthouse_syncing) | Get the node's syncing status
(Lighthouse specific).

## `/node/version`

Requests the beacon node's version.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/node/version`
Method | GET
JSON Encoding | String
Query Parameters | None
Typical Responses | 200

### Example Response

```json
"Lighthouse-0.2.0-unstable"
```

## `/node/syncing`

Requests the syncing status of the beacon node.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/node/syncing`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
	is_syncing: true,
	sync_status: {
	    starting_slot: 0,
    	current_slot: 100,
    	highest_slot: 200,
	}
}
```

## `/node/lighthouse_syncing`

Requests the syncing state of a Lighthouse beacon node. Lighthouse as a
custom sync protocol, this request gets Lighthouse-specific sync information.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/node/lighthouse_syncing`
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
