# Lighthouse REST API: `/validator`

The `/validator` endpoints provide the minimum functionality required for a validator
client to connect to the beacon node and produce blocks and attestations.

## Endpoints

HTTP Path | HTTP Method | Description |
| --- | -- |
[`/validator/duties`](#validatorduties) | GET | Provides block and attestation production information for validators.
[`/validator/duties/all`](#validatordutiesall) | GET |Provides block and attestation production information for all validators.
[`/validator/duties/active`](#validatordutiesactive) | GET | Provides block and attestation production information for all active validators.
[`/validator/block`](#validatorblockget) | GET | Retrieves the current beacon
block for the validator to publish.
[`/validator/block`](#validatorblockpost) | POST | Publishes a signed block to the
network.
[`/validator/attestation`](#validatorattestation) | GET | Retrieves the current best attestation for a validator to publish.
[`/validator/attestations`](#validatorattestations) | POST | Publishes a list
of raw unaggregated attestations to their appropriate subnets
[`/validator/aggregate_attestation`](#validatoraggregateattestation) | GET | Gets an aggregate attestation for validators to sign and publish.
[`/validator/aggregate_attestations`](#validatoraggregateattestation) | POST |
Publishes a list of aggregated attestations for validators who are aggregators
[`/validator/subscribe`](#validatorsubscribe) | POST | Subscribes a list of
validators to the beacon node for a particular duty/slot.

## `/validator/duties`

Request information about when a validator must produce blocks and attestations
at some given `epoch`. The information returned always refers to the canonical
chain and the same input parameters may yield different results after a re-org.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/duties`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Request Body

Expects the following object in the POST request body:

```
{
	epoch: Epoch,
	pubkeys: [PublicKey]
}
```

Duties are assigned on a per-epoch basis, all duties returned will contain
slots that are inside the given `epoch`. A set of duties will be returned for
each of the `pubkeys`.

Validators who are not known to the beacon chain (e.g., have not yet deposited)
will have `null` values for most fields.


### Returns

A set of duties for each given pubkey.

### Example

#### Request Body

```json
{
    "epoch": 1203,
    "pubkeys": [
        "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42"
    ]
}
```

_Note: for demonstration purposes the second pubkey is some unknown pubkey._

#### Response Body

```json
[
    {
        "validator_pubkey": "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "validator_index": 14935,
        "attestation_slot": 38511,
        "attestation_committee_index": 3,
        "attestation_committee_position": 39,
        "block_proposal_slots": [],
		"aggregator_modulo": 5,
    },
    {
        "validator_pubkey": "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42",
        "validator_index": null,
        "attestation_slot": null,
        "attestation_committee_index": null,
        "attestation_committee_position": null,
        "block_proposal_slots": []
		"aggregator_modulo": null,
    }
]
```

## `/validator/duties/all`

Returns the duties for all validators, equivalent to calling [Validator
Duties](#validator-duties) while providing all known validator public keys.

Considering that duties for non-active validators will just be `null`, it is
generally more efficient to query using [Active Validator
Duties](#active-validator-duties).

This endpoint will only return validators that were in the beacon state
in the given epoch. For example, if the query epoch is 10 and some validator
deposit was included in epoch 11, that validator will not be included in the
result.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/duties/all`
Method | GET
JSON Encoding | Object
Query Parameters | `epoch`
Typical Responses | 200

### Parameters

The duties returned will all be inside the given `epoch` (`Epoch`) query
parameter. This parameter is required.

### Returns

The return format is identical to the [Validator Duties](#validator-duties) response body.

## `/validator/duties/active`

Returns the duties for all active validators, equivalent to calling [Validator
Duties](#validator-duties) while providing all known validator public keys that
are active in the given epoch.

This endpoint will only return validators that were in the beacon state
in the given epoch. For example, if the query epoch is 10 and some validator
deposit was included in epoch 11, that validator will not be included in the
result.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/duties/active`
Method | GET
JSON Encoding | Object
Query Parameters | `epoch`
Typical Responses | 200

### Parameters

The duties returned will all be inside the given `epoch` (`Epoch`) query
parameter. This parameter is required.

### Returns

The return format is identical to the [Validator Duties](#validator-duties) response body.

## `/validator/block`

Produces and returns an unsigned `BeaconBlock` object.

The block will be produced with the given `slot` and the parent block will be the
highest block in the canonical chain that has a slot less than `slot`. The
block will still be produced if some other block is also known to be at `slot`
(i.e., it may produce a block that would be slashable if signed).

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/block`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`, `randao_reveal`
Typical Responses | 200

### Parameters


- `slot` (`Slot`): The slot number for which the block is to be produced.
- `randao_reveal` (`Signature`): 96 bytes `Signature` for the randomness.


### Returns

Returns a `BeaconBlock` object.

#### Response Body

```json
{
    "slot": 33,
    "parent_root": "0xf54de54bd33e33aee4706cffff4bd991bcbf522f2551ab007180479c63f4fe912",
    "state_root": "0x615c887bad27bc05754d627d941e1730e1b4c77b2eb4378c195ac8a8203bbf26",
    "body": {
      "randao_reveal": "0x8d7b2a32b026e9c79aae6ec6b83eabae89d60cacd65ac41ed7d2f4be9dd8c89c1bf7cd3d700374e18d03d12f6a054c23006f64f0e4e8b7cf37d6ac9a4c7d815c858120c54673b7d3cb2bb1550a4d659eaf46e34515677c678b70d6f62dbf89f",
      "eth1_data": {
        "deposit_root": "0x66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "deposit_count": 8,
        "block_hash": "0x2b32db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667151e"
      },
      "graffiti": "0x736967702f6c69676874686f7573652d302e312e312d7076572656c65617365",
      "proposer_slashings": [],
      "attester_slashings": [],
      "attestations": [],
      "deposits": [],
      "voluntary_exits": []
    }
}
```

## `/validator/attestation`

Produces and returns an unsigned `Attestation` from the current state.

The attestation will reference the `beacon_block_root` of the highest block in
the canonical chain with a slot equal to or less than the given `slot`.

An error will be returned if the given slot is more than
`SLOTS_PER_HISTORICAL_VECTOR` slots behind the current head block.

This endpoint is not protected against slashing. Signing the returned
attestation may result in a slashable offence.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/attestation`
Method | GET
JSON Encoding | Object
Query Parameters | `slot`, `committee_index`
Typical Responses | 200

### Parameters


- `slot` (`Slot`): The slot number for which the attestation is to be produced.
- `committee_index` (`CommitteeIndex`): The index of the committee that makes the attestation.


### Returns

Returns a `Attestation` object with a default signature. The `signature` field should be replaced by the valid signature.

#### Response Body

```json
{
    "aggregation_bits": "0x01",
    "data": {
        "slot": 100,
        "index": 0,
        "beacon_block_root": "0xf22e4ec281136d119eabcd4d9d248aeacd042eb63d8d7642f73ad3e71f1c9283",
        "source": {
            "epoch": 2,
            "root": "0x34c1244535c923f08e7f83170d41a076e4f1ec61013846b3a615a1d109d3c329"
        },
        "target": {
            "epoch": 3,
            "root": "0xaefd23b384994dc0c1a6b77836bdb2f24f209ebfe6c4819324d9685f4a43b4e1"
        }
    },
    "signature": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
}
```

## `/validator/block`

Accepts a `SignedBeaconBlock` for verification. If it is valid, it will be
imported into the local database and published on the network. Invalid blocks
will not be published to the network.

A block may be considered invalid because it is fundamentally incorrect, or its
parent has not yet been imported.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/block`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200/202


### Request Body

Expects a JSON encoded `SignedBeaconBlock` in the POST request body:

### Returns

Returns a null object if the block passed all block validation and is published to the network.
Else, returns a processing error description.

### Example

### Request Body

```json
{
  "message": {
    "slot": 33,
    "parent_root": "0xf54de54bd33e33aee4706cffff4bd991bcbf522f2551ab007180479c63f4fe912",
    "state_root": "0x615c887bad27bc05754d627d941e1730e1b4c77b2eb4378c195ac8a8203bbf26",
    "body": {
      "randao_reveal": "0x8d7b2a32b026e9c79aae6ec6b83eabae89d60cacd65ac41ed7d2f4be9dd8c89c1bf7cd3d700374e18d03d12f6a054c23006f64f0e4e8b7cf37d6ac9a4c7d815c858120c54673b7d3cb2bb1550a4d659eaf46e34515677c678b70d6f62dbf89f",
      "eth1_data": {
        "deposit_root": "0x66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "deposit_count": 8,
        "block_hash": "0x2b32db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667151e"
      },
      "graffiti": "0x736967702f6c69676874686f7573652d302e312e312d7076572656c65617365",
      "proposer_slashings": [

      ],
      "attester_slashings": [

      ],
      "attestations": [

      ],
      "deposits": [

      ],
      "voluntary_exits": [

      ]
    }
  },
  "signature": "0x965ced900dbabd0a78b81a0abb5d03407be0d38762104316416347f2ea6f82652b5759396f402e85df8ee18ba2c60145037c73b1c335f4272f1751a1cd89862b7b4937c035e350d0108554bd4a8930437ec3311c801a65fe8e5ba022689b5c24"
}
```

## `/validator/attestation`

Accepts an `Attestation` for verification. If it is valid, it will be imported
into the local database and published to the network. Invalid attestations will
not be published to the network.

An attestation may be considered invalid because it is fundamentally incorrect
or because the beacon node has not imported the relevant blocks required to
verify it.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/attestation`
Method | POST
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200/202


### Request Body

Expects a JSON encoded signed `Attestation` object in the POST request body. In
accordance with the naive aggregation scheme, the attestation _must_ have
exactly one of the `attestation.aggregation_bits` fields set.

### Returns

Returns a null object if the attestation passed all validation and is published to the network.
Else, returns a processing error description.

### Example

### Request Body

```json
{
  "aggregation_bits": "0x03",
  "data": {
    "slot": 3,
    "index": 0,
    "beacon_block_root": "0x0b6a1f7a9baa38d00ef079ba861b7587662565ca2502fb9901741c1feb8bb3c9",
    "source": {
      "epoch": 0,
      "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    "target": {
      "epoch": 0,
      "root": "0xad2c360ab8c8523db278a7d7ced22f3810800f2fdc282defb6db216689d376bd"
    }
  },
  "signature": "0xb76a1768c18615b5ade91a92e7d2ed0294f7e088e56e30fbe7e3aa6799c443b11bccadd578ca2cbd95d395ab689b9e4d03c88a56641791ab38dfa95dc1f4d24d1b19b9d36c96c20147ad03$649bd3c6c7e8a39cf2ffb99e07b4964d52854559f"
}
```
