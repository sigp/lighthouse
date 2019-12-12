# Lighthouse REST API: `/validator`

The `/validator` endpoints provide the minimum functionality required for a validator
client to connect to the beacon node and produce blocks and attestations.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/validator/duties`](#validatorduties) | Provides block and attestation production information for validators.
[`/validator/duties/all`](#validatordutiesall) | Provides block and attestation production information for all validators.
[`/validator/duties/active`](#validatordutiesactive) | Provides block and attestation production information for all active validators.

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
        "block_proposal_slots": []
    },
    {
        "validator_pubkey": "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42",
        "validator_index": null,
        "attestation_slot": null,
        "attestation_committee_index": null,
        "attestation_committee_position": null,
        "block_proposal_slots": []
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
