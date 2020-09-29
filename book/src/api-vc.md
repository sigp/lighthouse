# Validator Client API

Lighthouse REST API: `/lighthouse`

The `/lighthouse` endpoints provide lighthouse-specific information about the beacon node.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/lighthouse/version`](#lighthouseversion) | Get the Lighthouse software version
[`/lighthouse/health`](#lighthousehealth) | Get information about the host machine

## `/lighthouse/version`

Returns the software version and `git` commit hash for the Lighthouse binary.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/version`
Method | GET
JSON Encoding | Object
Query Parameters | None
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

### Example Response

```json
{
    "data": {
        "version": "Lighthouse/v0.2.11-fc0654fbe+/x86_64-linux"
    }
}
```

## `/lighthouse/health`

Returns information regarding the health of the host machine.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/health`
Method | GET
JSON Encoding | Object
Query Parameters | No
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

*Note: this endpoint is presently only available on Linux.*

### Example Response

```json
{
    "data": {
        "pid": 1476293,
        "pid_num_threads": 19,
        "pid_mem_resident_set_size": 4009984,
        "pid_mem_virtual_memory_size": 1306775552,
        "sys_virt_mem_total": 33596100608,
        "sys_virt_mem_available": 23073017856,
        "sys_virt_mem_used": 9346957312,
        "sys_virt_mem_free": 22410510336,
        "sys_virt_mem_percent": 31.322334,
        "sys_loadavg_1": 0.98,
        "sys_loadavg_5": 0.98,
        "sys_loadavg_15": 1.01
    }
}
```

## `/lighthouse/validators`

Lists all validators managed by this validator client.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/validators`
Method | GET
JSON Encoding | Object
Query Parameters | No
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

### Example Response

```json
{
    "data": [
        {
            "enabled": true,
            "voting_pubkey": "0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde"
        },
        {
            "enabled": true,
            "voting_pubkey": "0xb0441246ed813af54c0a11efd53019f63dd454a1fa2a9939ce3c228419fbe113fb02b443ceeb38736ef97877eb88d43a"
        },
        {
            "enabled": true,
            "voting_pubkey": "0xad77e388d745f24e13890353031dd8137432ee4225752642aad0a2ab003c86620357d91973b6675932ff51f817088f38"
        }
    ]
}
```

## `/lighthouse/validators/:voting_pubkey`

Get a validator by their `voting_pubkey`.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/validators/:voting_pubkey`
Method | GET
JSON Encoding | Object
Query Parameters | No
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

### Example Path

```
localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde
```

### Example Response

```json
{
    "data": {
        "enabled": true,
        "voting_pubkey": "0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde"
    }
}
```

## `/lighthouse/validators/`

Create a new validator

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/validators/:voting_pubkey`
Method | GET
JSON Encoding | Object
Query Parameters | No
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

### Example Request

```json
[
	{
		"enable": true,
		"validator_desc": "validator 0",
		"deposit_gwei": "32000000000"
	}
]
```

### Example Response

```json
{
    "data": {
        "mnemonic": "until stem before clip receive exercise alter math like slide great entry thrive easy water glance proof gravity project intact state core harbor luggage",
        "validators": [
            {
                "enabled": true,
                "voting_pubkey": "0x82a1ef6fcdc5bef7281c9d63d1910545077baa6e61533c3d09d178d22a473ad254a04c94a94d45d43c6f54a53f98835f",
                "eth1_deposit_tx_data": "0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120447967560b728fcf6e33305b98e9c644650370901d404c6261848cad7f742916000000000000000000000000000000000000000000000000000000000000003082a1ef6fcdc5bef7281c9d63d1910545077baa6e61533c3d09d178d22a473ad254a04c94a94d45d43c6f54a53f98835f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020004b3558edfb5bd3be9f9314f5bc01715b60b6a07795ebcb9ea20bd3ef150b2b0000000000000000000000000000000000000000000000000000000000000060964e12af6b1d4a53fa75275846580aab255dc2c618c644079f92000a00a4962d13a673465d9e8d80faf55e52d042f21006f5743330ea6db5d24e4034dbb293b00ef1336b90861857f81975b2d3c3b31c38ab7a1dacbe3d32b9b2a0ceb01c398d",
                "deposit_gwei": "32000000000"
            }
        ]
    }
}
```

## `/lighthouse/validators/mnemonic`

Create a new validator from an existing mnemonic.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/lighthouse/validators/mnemonic`
Method | GET
JSON Encoding | Object
Query Parameters | No
Required Headers | [`Authorization`](./api-vc-auth-header.md)
Typical Responses | 200

### Example Request

```json
{
    "mnemonic": "theme onion deal plastic claim silver fancy youth lock ordinary hotel elegant balance ridge web skill burger survey demand distance legal fish salad cloth",
    "key_derivation_path_offset": 0,
    "validators": [
        {
            "enable": true,
            "validator_desc": "validator 0",
            "deposit_gwei": "32000000000"
        }
    ]
}
```

### Example Response

```json
{
    "data": [
		{
			"enabled": true,
			"voting_pubkey": "0x82a1ef6fcdc5bef7281c9d63d1910545077baa6e61533c3d09d178d22a473ad254a04c94a94d45d43c6f54a53f98835f",
			"eth1_deposit_tx_data": "0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120447967560b728fcf6e33305b98e9c644650370901d404c6261848cad7f742916000000000000000000000000000000000000000000000000000000000000003082a1ef6fcdc5bef7281c9d63d1910545077baa6e61533c3d09d178d22a473ad254a04c94a94d45d43c6f54a53f98835f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020004b3558edfb5bd3be9f9314f5bc01715b60b6a07795ebcb9ea20bd3ef150b2b0000000000000000000000000000000000000000000000000000000000000060964e12af6b1d4a53fa75275846580aab255dc2c618c644079f92000a00a4962d13a673465d9e8d80faf55e52d042f21006f5743330ea6db5d24e4034dbb293b00ef1336b90861857f81975b2d3c3b31c38ab7a1dacbe3d32b9b2a0ceb01c398d",
			"deposit_gwei": "32000000000"
		}
	]
}
```
