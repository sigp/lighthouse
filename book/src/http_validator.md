# Lighthouse REST API: `/validator`

## Endpoints

Table of endpoints:

HTTP Path | Description |
| --- | -- |
[`/validator/duties`](#validator-duties) | Provides block and attestation production information for validators.

## Validator Duties

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
Typical Responses | 200, 404

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
        "98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42"
    ]
}
```

_Note: for demonstration purposes the second pubkey is some unknown pubkey._

#### Response Body

```json
[
    {
        "validator_pubkey": "98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "validator_index": 14935,
        "attestation_slot": 38511,
        "attestation_committee_index": 3,
        "attestation_committee_position": 39,
        "block_proposal_slots": [14936]
    },
    {
        "validator_pubkey": "42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42",
        "validator_index": null,
        "attestation_slot": null,
        "attestation_committee_index": null,
        "attestation_committee_position": null,
        "block_proposal_slots": []
    }
]
```
