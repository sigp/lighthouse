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
	    starting_slot: 1213123123123123123123123122,
    	current_slot: 1213123123123123123123123122,
    	highest_slot: 1213123123123123123123123122,
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

```json
{
	"syncing_finalized": {
		"start_slot": 10,
		"head_slot": 20,
		"head_root":"0x0000000000000000000000000000000000000000000000000100000000000000"
		}
}
```
