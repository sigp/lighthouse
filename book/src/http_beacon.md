# Lighthouse REST API: `/beacon`

## Endpoints

Table of endpoints:

HTTP Path | Description |
| --- | -- |
[`/beacon/head`](#beacon-head) | Info about the block at the head of the chain.
[`/beacon/block_root`](#block-root) | Resolve a slot to a block root.
[`/beacon/block`](#beacon-block) | Get a `BeaconBlock` by slot or root.
[`/beacon/state_root`](#state-root) | Resolve a slot to a state root.
[`/beacon/state`](#beacon-state) | Get a `BeaconState` by slot or root
[`/beacon/validators`](#validators) | Query for one or more validators
[`/beacon/validators/all`](#all-validators) | Get all validators
[`/beacon/validators/active`](#active-validators) | Get all active validators

## Beacon Head

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

```
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

## Block Root

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

```
"0xc35ddf4e71c31774e0594bd7eb32dfe50b54dbc40abd594944254b4ec8895196"
```

## Beacon Block

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

Returns an object containing a single [`BeaconBlock`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/core/0_beacon-chain.md#beaconblock) and it's signed root.

### Example Response

```
{
	root: "0x98e5edb27e53d238a9524590e62b1413",
	beacon_block: {
		slot: 42,
		parent_root: "0xabfb96c38165791636acaf72c4529c0b",
		...
	},
}
```


_Truncated for brevity._

## State Root

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

```
"0xf15690b6be4ed42ea1ee0741eb4bfd4619d37be8229b84b4ddd480fb028dcc8f"
```

## Beacon State

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
[`BeaconState`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/core/0_beacon-chain.md#beaconstate)
and its tree hash root.

### Example Response

```
{
	root: "0x68861c0151d232c75b8dfa24b8a07b65",
	beacon_state: {
		genesis_time: 1566444600,
		slot: 42,
		...
	},
}
```

_Truncated for brevity._

## Validators

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
Typical Responses | 200, 404

### POST body

Expects the following object:

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

### Example Response

```
[
    {
        "pubkey": "98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "validator_index": 14935,
        "balance": 3224668436,
        "validator": {
            "pubkey": "98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
            "withdrawal_credentials": "0x00b7bec22d5bda6b2cca1343d4f640d0e9ccc204a06a73703605c590d4c0d28e",
            "effective_balance": 3200000000,
            "slashed": false,
            "activation_eligibility_epoch": 0,
            "activation_epoch": 0,
            "exit_epoch": 18446744073709551615,
            "withdrawable_epoch": 18446744073709551615
        }
    }
]
```

## All Validators

Returns all validators.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/validators/all`
Method | GET
JSON Encoding | Object
Query Parameters | `state_root` (optional)
Typical Responses | 200, 404

### Parameters

The optional `state_root` query parameter indicates which `BeaconState` should be used to collect
the information. When omitted, the canonical head state will be used.

### Returns

The return format is identical to [Validators](#validators).

## Active Validators

Returns all validators that are active in the state defined by `state_root`.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/beacon/validators/active`
Method | GET
JSON Encoding | Object
Query Parameters | `state_root` (optional)
Typical Responses | 200, 404

### Parameters

The optional `state_root` query parameter indicates which `BeaconState` should be used to collect
the information. When omitted, the canonical head state will be used.

### Returns

The return format is identical to [Validators](#validators).
