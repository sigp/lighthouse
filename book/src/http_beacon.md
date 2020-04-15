# Lighthouse REST API: `/beacon`

The `/beacon` endpoints provide information about the canonical head of the
beacon chain and also historical information about beacon blocks and states.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/beacon/attester_slashing`](#beaconattester_slashing) | Insert an attester slashing
[`/beacon/block`](#beaconblock) | Get a `BeaconBlock` by slot or root.
[`/beacon/block_root`](#beaconblock_root) | Resolve a slot to a block root.
[`/beacon/committees`](#beaconcommittees) | Get the shuffling for an epoch.
[`/beacon/head`](#beaconhead) | Info about the block at the head of the chain.
[`/beacon/heads`](#beaconheads) | Returns a list of all known chain heads.
[`/beacon/proposer_slashing`](#beaconproposer_slashing) | Insert a proposer slashing
[`/beacon/state`](#beaconstate) | Get a `BeaconState` by slot or root.
[`/beacon/state_root`](#beaconstate_root) | Resolve a slot to a state root.
[`/beacon/state/genesis`](#beaconstategenesis) | Get a `BeaconState` at genesis.
[`/beacon/genesis_time`](#beacongenesis_time) | Get the genesis time from the beacon state.
[`/beacon/fork`](#beaconfork) | Get the fork of the head of the chain.
[`/beacon/validators`](#beaconvalidators) | Query for one or more validators.
[`/beacon/validators/active`](#beaconvalidatorsactive) | Get all active validators.
[`/beacon/validators/all`](#beaconvalidatorsall) | Get all validators.

## `/beacon/attester_slashing`

Accepts an `attester_slashing` and verifies it. If it is valid, it is added to the operations pool for potential inclusion in a future block. Returns a 400 error if the `attester_slashing` is invalid.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/attester_slashing`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200/400

### Parameters

Expects the following object in the POST request body:

```
{
    attestation_1: {
        attesting_indices: [u64],
        data: {
            slot: Slot,
            index: u64,
            beacon_block_root: Bytes32,
            source: {
                epoch: Epoch,
                root: Bytes32
            },
            target: {
                epoch: Epoch,
                root: Bytes32
            }
        }
        signature: Bytes32
    },
    attestation_2: {
        attesting_indices: [u64],
        data: {
            slot: Slot,
            index: u64,
            beacon_block_root: Bytes32,
            source: {
                epoch: Epoch,
                root: Bytes32
            },
            target: {
                epoch: Epoch,
                root: Bytes32
            }
        }
        signature: Bytes32
    }
}
```

### Returns

Returns `true` if the attester slashing was inserted successfully, or the corresponding error if it failed.

### Example

### Request Body

```json
{
	"attestation_1": {
		"attesting_indices": [0],
		"data": {
			"slot": 1,
			"index": 0,
			"beacon_block_root": "0x0000000000000000000000000000000000000000000000000100000000000000",
			"source": {
				"epoch": 1,
				"root": "0x0000000000000000000000000000000000000000000000000100000000000000"
			},
			"target": {
				"epoch": 1,
				"root": "0x0000000000000000000000000000000000000000000000000100000000000000"
			}
		},
		"signature": "0xb47f7397cd944b8d5856a13352166bbe74c85625a45b14b7347fc2c9f6f6f82acee674c65bc9ceb576fcf78387a6731c0b0eb3f8371c70db2da4e7f5dfbc451730c159d67263d3db56b6d0e009e4287a8ba3efcacac30b3ae3447e89dc71b5b9"
	},
	"attestation_2": {
		"attesting_indices": [0],
		"data": {
			"slot": 1,
			"index": 0,
			"beacon_block_root": "0x0000000000000000000000000000000000000000000000000100000000000000",
			"source": {
				"epoch": 1,
				"root": "0x0000000000000000000000000000000000000000000000000100000000000000"
			},
			"target": {
				"epoch": 1,
				"root": "0x0000000000000000000000000000000000000000000000000200000000000000"
			}
		},
		"signature": "0x93fef587a63acf72aaf8df627718fd43cb268035764071f802ffb4370a2969d226595cc650f4c0bf2291ae0c0a41fcac1700f318603d75d34bcb4b9f4a8368f61eeea0e1f5d969d92d5073ba5fbadec102b45ec87d418d25168d2e3c74b9fcbb"
	}
}
```

_Note: data sent here is for demonstration purposes only_

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
            "proposer_index": 14,
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
Typical Responses | 200/500

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

## `/beacon/proposer_slashing`

Accepts a `proposer_slashing` and verifies it. If it is valid, it is added to the operations pool for potential inclusion in a future block. Returns an 400 error if the `proposer_slashing` is invalid.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/proposer_slashing`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200/400

### Request Body

Expects the following object in the POST request body:

```
{
    proposer_index: u64,
    header_1: {
        slot: Slot,
        parent_root: Bytes32,
        state_root: Bytes32,
        body_root: Bytes32,
        signature: Bytes32
    },
    header_2: {
        slot: Slot,
        parent_root: Bytes32,
        state_root: Bytes32,
        body_root: Bytes32,
        signature: Bytes32
    }
}
```

### Returns

Returns `true` if the proposer slashing was inserted successfully, or the corresponding error if it failed.

### Example

### Request Body

```json
{
	"proposer_index": 0,
    "header_1": {
        "slot": 0,
        "parent_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "state_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "body_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "signature": "0xb8970d1342c6d5779c700ec366efd0ca819937ca330960db3ca5a55eb370a3edd83f4cbb2f74d06e82f934fcbd4bb80609a19c2254cc8b3532a4efff9e80edf312ac735757c059d77126851e377f875593e64ba50d1dffe69a809a409202dd12"
    },
    "header_2": {
        "slot": 0,
        "parent_root": "0x0202020202020202020202020202020202020202020202020202020202020202",
        "state_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "body_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "signature": "0xb60e6b348698a34e59b22e0af96f8809f977f00f95d52375383ade8d22e9102270a66c6d52b0434214897e11ca4896871510c01b3fd74d62108a855658d5705fcfc4ced5136264a1c6496f05918576926aa191b1ad311b7e27f5aa2167aba294"
    }
}
```

_Note: data sent here is for demonstration purposes only_



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
[`BeaconState`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#beaconstate)
and its tree hash root.

### Example Response

```json
{
    "root": "0x528e54ca5d4c957729a73f40fc513ae312e054c7295775c4a2b21f423416a72b",
    "beacon_state": {
        "genesis_time": 1575652800,
        "genesis_validators_root": "0xa8a9226edee1b2627fb4117d7dea4996e64dec2998f37f6e824f74f2ce39a538",
        "slot": 18478
	}
}
```

_Truncated for brevity._

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
[`BeaconState`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#beaconstate).

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

Returns an object containing the [`Fork`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#fork) of the current head.

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
