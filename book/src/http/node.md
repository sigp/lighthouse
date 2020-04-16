# Lighthouse REST API: `/node`

The `/node` endpoints provide information about the lighthouse beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/node/version`](#nodeversion) | Get the node's version.
[`/node/syncing`](#nodesyncing) | Get the node's syncing status.

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
