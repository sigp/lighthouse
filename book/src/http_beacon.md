# Lighthouse REST API: `/beacon`

The `/beacon` endpoints provide information about the canonical head of the
beacon chain and also historical information about beacon blocks and states.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/beacon/head`](#beaconhead) | Info about the block at the head of the chain.
[`/beacon/heads`](#beaconheads) | Returns a list of all known chain heads.
[`/beacon/block_root`](#beaconblock_root) | Resolve a slot to a block root.
[`/beacon/block`](#beaconblock) | Get a `SignedBeaconBlock` by slot or root.
[`/beacon/state_root`](#beaconstate_root) | Resolve a slot to a state root.
[`/beacon/state`](#beaconstate) | Get a `BeaconState` by slot or root.
[`/beacon/state/genesis`](#beaconstategenesis) | Get a `BeaconState` at genesis.
[`/beacon/genesis_time`](#beacongenesis_time) | Get the genesis time from the beacon state.
[`/beacon/fork`](#beaconfork) | Get the fork of the head of the chain.
[`/beacon/validators`](#beaconvalidators) | Query for one or more validators.
[`/beacon/validators/all`](#beaconvalidatorsall) | Get all validators.
[`/beacon/validators/active`](#beaconvalidatorsactive) | Get all active validators.
[`/beacon/committees`](#beaconcommittees) | Get the shuffling for an epoch.

## `/beacon/head`

Requests information about the head of the beacon chain, from the node's
perspective.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/head`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "slot": 37923,
    "block_root": "0xe865d4805395a0776b8abe46d714a9e64914ab8dc5ff66624e5a1776bcc1684b",
    "state_root": "0xe500e3567ab273c9a6f8a057440deff476ab236f0983da27f201ee9494a879f0",
    "finalized_slot": 37856,
    "finalized_block_root": "0xbdae152b62acef1e5c332697567d2b89e358628790b8273729096da670b23e86",
    "justified_slot": 37888,
    "justified_block_root": "0x01c2f516a407d8fdda23cad4ed4381e4ab8913d638f935a2fe9bd00d6ced5ec4",
    "previous_justified_slot": 37856,
    "previous_justified_block_root": "0xbdae152b62acef1e5c332697567d2b89e358628790b8273729096da670b23e86"
}
```

## `/beacon/heads`

Returns the roots of all known head blocks. Only one of these roots is the
canonical head and that is decided by the fork choice algorithm. See [`/beacon/head`](#beaconhead) for the canonical head.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/heads`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
[
    {
        "beacon_block_root": "0x226b2fd7c5f3d31dbb21444b96dfafe715f0017cd16545ecc4ffa87229496a69",
        "beacon_block_slot": 38373
    },
    {
        "beacon_block_root": "0x41ed5b253c4fc841cba8a6d44acbe101866bc674c3cfa3c4e9f7388f465aa15b",
        "beacon_block_slot": 38375
    }
]
```

## `/beacon/block_root`

Returns the block root for the given slot in the canonical chain. If there
is a re-org, the same slot may return a different root.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/block_root`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`
Typical Responses | 200, 404

## Parameters

- `slot` (`Slot`): the slot to be resolved to a root.

### Example Response

```json
"0xc35ddf4e71c31774e0594bd7eb32dfe50b54dbc40abd594944254b4ec8895196"
```

## `/beacon/block`

Request that the node return a beacon chain block that matches the provided
criteria (a block `root` or beacon chain `slot`). Only one of the parameters
should be provided as a criteria.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/block`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`, `root`
Typical Responses | 200, 404

### Parameters

Accepts **only one** of the following parameters:

- `slot` (`Slot`): Query by slot number. Any block returned must be in the canonical chain (i.e.,
either the head or an ancestor of the head).
- `root` (`Bytes32`): Query by tree hash root. A returned block is not required to be in the
canonical chain.

### Returns

Returns an object containing a single [`SignedBeaconBlock`](https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/beacon-chain.md#signedbeaconblock) and the block root of the inner [`BeaconBlock`](https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/beacon-chain.md#beaconblock).

### Example Response

```json
{
    "root": "0xc35ddf4e71c31774e0594bd7eb32dfe50b54dbc40abd594944254b4ec8895196",
    "beacon_block": {
        "message": {
            "slot": 0,
            "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "state_root": "0xf15690b6be4ed42ea1ee0741eb4bfd4619d37be8229b84b4ddd480fb028dcc8f",
            "body": {
                "randao_reveal": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "eth1_data": {
                    "deposit_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "deposit_count": 0,
                    "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "graffiti": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "proposer_slashings": [],
                "attester_slashings": [],
                "attestations": [],
                "deposits": [],
                "voluntary_exits": []
            }
        },
        "signature": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    }
}
```

## `/beacon/state_root`

Returns the state root for the given slot in the canonical chain. If there
is a re-org, the same slot may return a different root.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/state_root`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`
Typical Responses | 200, 404

## Parameters

- `slot` (`Slot`): the slot to be resolved to a root.

### Example Response

```json
"0xf15690b6be4ed42ea1ee0741eb4bfd4619d37be8229b84b4ddd480fb028dcc8f"
```

## `/beacon/state`

Request that the node return a beacon chain state that matches the provided
criteria (a state `root` or beacon chain `slot`). Only one of the parameters
should be provided as a criteria.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/state`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`, `root`
Typical Responses | 200, 404

### Parameters

Accepts **only one** of the following parameters:

- `slot` (`Slot`): Query by slot number. Any state returned must be in the canonical chain (i.e.,
either the head or an ancestor of the head).
- `root` (`Bytes32`): Query by tree hash root. A returned state is not required to be in the
canonical chain.

### Returns

Returns an object containing a single
[`BeaconState`](https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beaconstate)
and its tree hash root.

### Example Response

```json
{
    "root": "0x528e54ca5d4c957729a73f40fc513ae312e054c7295775c4a2b21f423416a72b",
    "beacon_state": {
        "genesis_time": 1575652800,
        "slot": 18478
	}
}
```

_Truncated for brevity._

## `/beacon/state/genesis`

Request that the node return a beacon chain state at genesis (slot 0).

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/state/genesis`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200


### Returns

Returns an object containing the genesis
[`BeaconState`](https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beaconstate).

### Example Response

```json
{
    "genesis_time": 1581576353,
    "slot": 0,
    "fork": {
        "previous_version": "0x00000000",
        "current_version": "0x00000000",
        "epoch": 0
    },
}
```

_Truncated for brevity._

## `/beacon/genesis_time`

Request that the node return the genesis time from the beacon state.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/genesis_time`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200


### Returns

Returns an object containing the genesis time.

### Example Response

```json
1581576353
```

## `/beacon/fork`

Request that the node return the `fork` of the current head.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/fork`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200


### Returns

Returns an object containing the [`Fork`](https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#fork) of the current head.

### Example Response

```json
{
    "previous_version": "0x00000000",
    "current_version": "0x00000000",
    "epoch": 0
}
```

## `/beacon/validators`

Request that the node returns information about one or more validator public
keys. This request takes the form of a `POST` request to allow sending a large
number of pubkeys in the request.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/validators`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Request Body

Expects the following object in the POST request body:

```
{
	state_root: Bytes32,
	pubkeys: [PublicKey]
}
```

The `state_root` field indicates which `BeaconState` should be used to collect
the information. The `state_root` is optional and omitting it will result in
the canonical head state being used.


### Returns

Returns an object describing several aspects of the given validator.

### Example

### Request Body

```json
{
    "pubkeys": [
        "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42"
    ]
}
```

_Note: for demonstration purposes the second pubkey is some unknown pubkey._

### Response Body

```json
[
    {
        "pubkey": "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "validator_index": 14935,
        "balance": 3228885987,
        "validator": {
            "pubkey": "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
            "withdrawal_credentials": "0x00b7bec22d5bda6b2cca1343d4f640d0e9ccc204a06a73703605c590d4c0d28e",
            "effective_balance": 3200000000,
            "slashed": false,
            "activation_eligibility_epoch": 0,
            "activation_epoch": 0,
            "exit_epoch": 18446744073709551615,
            "withdrawable_epoch": 18446744073709551615
        }
    },
    {
        "pubkey": "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42",
        "validator_index": null,
        "balance": null,
        "validator": null
    }
]
```

## `/beacon/validators/all`

Returns all validators.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/validators/all`
Method | GET
JSON Encoding | Object
Query Parameters | `state_root` (optional)
Typical Responses | 200

### Parameters

The optional `state_root` (`Bytes32`) query parameter indicates which
`BeaconState` should be used to collect the information. When omitted, the
canonical head state will be used.

### Returns

The return format is identical to the [`/beacon/validators`](#beaconvalidators) response body.

## `/beacon/validators/active`

Returns all validators that are active in the state defined by `state_root`.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/validators/active`
Method | GET
JSON Encoding | Object
Query Parameters | `state_root` (optional)
Typical Responses | 200

### Parameters

The optional `state_root` (`Bytes32`) query parameter indicates which
`BeaconState` should be used to collect the information. When omitted, the
canonical head state will be used.

### Returns

The return format is identical to the [`/beacon/validators`](#beaconvalidators) response body.

## `/beacon/committees`

Request the committees (a.k.a. "shuffling") for all slots and committee indices
in a given `epoch`.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/committees`
Method | GET
JSON Encoding | Object
Query Parameters | `epoch`
Typical Responses | 200

### Parameters

The `epoch` (`Epoch`) query parameter is required and defines the epoch for
which the committees will be returned. All slots contained within the response will
be inside this epoch.

### Returns

A list of beacon committees.

### Example Response

```json
[
    {
        "slot": 4768,
        "index": 0,
        "committee": [
            1154,
            492,
            9667,
            3089,
            8987,
            1421,
            224,
            11243,
            2127,
            2329,
            188,
            482,
            486
        ]
    },
    {
        "slot": 4768,
        "index": 1,
        "committee": [
            5929,
            8482,
            5528,
            6130,
            14343,
            9777,
            10808,
            12739,
            15234,
            12819,
            5423,
            6320,
            9991
        ]
    }
]
```

_Truncated for brevity._
