# Lighthouse REST API: `/node`

The `/node` endpoints provide information about the lighthouse beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/node/version`](#nodeversion) | Get the node's version.
[`/node/syncing`](#nodesyncing) | Get the node's syncing status.
[`/node/health`](#nodehealth)   | Get the node's health.

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

## `/node/health`

Requests information about the health of the beacon node.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/node/health`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "pid": 96160,
    "pid_num_threads": 30,
    "pid_mem_resident_set_size": 55476224,
    "pid_mem_virtual_memory_size": 2081382400,
    "sys_virt_mem_total": 16721076224,
    "sys_virt_mem_available": 7423197184,
    "sys_virt_mem_used": 8450183168,
    "sys_virt_mem_free": 3496345600,
    "sys_virt_mem_percent": 55.605743,
    "sys_loadavg_1": 1.56,
    "sys_loadavg_5": 2.61,
    "sys_loadavg_15": 2.43
}
```
