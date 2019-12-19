# Lighthouse REST API: `/consensus`

The `/consensus` endpoints provide information on results of the proof-of-stake
voting process used for finality/justification under Casper FFG.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/consensus/global_votes`](#consensusglobal_votes) | A global vote count for a given epoch.
[`/consensus/individual_votes`](#consensusindividual_votes) | A per-validator breakdown of votes in a given epoch.

## `/consensus/global_votes`

Returns a global count of votes for some given `epoch`. The results are included
both for the current and previous (`epoch - 1`) epochs since both are required
by the beacon node whilst performing per-epoch-processing.

Generally, you should consider the "current" values to be incomplete and the
"previous" values to be final. This is because validators can continue to
include attestations from the _current_ epoch in the _next_ epoch, however this
is not the case for attestations from the _previous_ epoch.

```
                  `epoch` query parameter
				              |
				              |     --------- values are calcuated here
                              |     |
							  v     v
Epoch:  |---previous---|---current---|---next---|

                          |-------------|
						         ^
                                 |
		       window for including "current" attestations
					        in a block
```

The votes are expressed in terms of staked _effective_ `Gwei` (i.e., not the number of
individual validators). For example, if a validator has 32 ETH staked they will
increase the `current_epoch_attesting_gwei` figure by `32,000,000,000` if they
have an attestation included in a block during the current epoch. If this
validator has more than 32 ETH, that extra ETH will not count towards their
vote (that is why it is _effective_ `Gwei`).

The following fields are returned:

- `current_epoch_active_gwei`: the total staked gwei that was active (i.e.,
	able to vote) during the current epoch.
- `current_epoch_attesting_gwei`: the total staked gwei that had one or more
    attestations included in a block during the current epoch (multiple
	attestations by the same validator do not increase this figure).
- `current_epoch_target_attesting_gwei`: the total staked gwei that attested to
	the majority-elected Casper FFG target epoch during the current epoch. This
	figure must be equal to or less than `current_epoch_attesting_gwei`.
- `previous_epoch_active_gwei`: as above, but during the previous epoch.
- `previous_epoch_attesting_gwei`: see `current_epoch_attesting_gwei`.
- `previous_epoch_target_attesting_gwei`: see `current_epoch_target_attesting_gwei`.
- `previous_epoch_head_attesting_gwei`: the total staked gwei that attested to a
	head beacon block that is in the canonical chain.

From this data you can calculate some interesting figures:

#### Participation Rate

`previous_epoch_attesting_gwei / previous_epoch_active_gwei`

Expresses the ratio of validators that managed to have an attestation
voting upon the previous epoch included in a block.

#### Justification/Finalization Rate

`previous_epoch_target_attesting_gwei / previous_epoch_active_gwei`

When this value is greater than or equal to `2/3` it is possible that the
beacon chain may justify and/or finalize the epoch.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/consensus/global_votes`
Method | GET
JSON Encoding | Object
Query Parameters | `epoch`
Typical Responses | 200

### Parameters

Requires the `epoch` (`Epoch`) query parameter to determine which epoch will be
considered the current epoch.

### Returns

A report on global validator voting participation.

### Example

```json
{
    "current_epoch_active_gwei": 52377600000000,
    "previous_epoch_active_gwei": 52377600000000,
    "current_epoch_attesting_gwei": 50740900000000,
    "current_epoch_target_attesting_gwei": 49526000000000,
    "previous_epoch_attesting_gwei": 52377600000000,
    "previous_epoch_target_attesting_gwei": 51063400000000,
    "previous_epoch_head_attesting_gwei": 9248600000000
}
```

## `/consensus/individual_votes`

Returns a per-validator summary of how that validator performed during the
current epoch.

The [Global Votes](#consensusglobal_votes) endpoint is the summation of all of these
individual values, please see it for definitions of terms like "current_epoch",
"previous_epoch" and "target_attester".

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/consensus/individual_votes`
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

### Returns

A report on the validators voting participation.

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
        "epoch": 1203,
        "pubkey": "0x98f87bc7c8fa10408425bbeeeb3dc387e3e0b4bd92f57775b60b39156a16f9ec80b273a64269332d97bdb7d93ae05a16",
        "validator_index": 14935,
        "vote": {
            "is_slashed": false,
            "is_withdrawable_in_current_epoch": false,
            "is_active_in_current_epoch": true,
            "is_active_in_previous_epoch": true,
            "current_epoch_effective_balance_gwei": 3200000000,
            "is_current_epoch_attester": true,
            "is_current_epoch_target_attester": true,
            "is_previous_epoch_attester": true,
            "is_previous_epoch_target_attester": true,
            "is_previous_epoch_head_attester": false
        }
    },
    {
        "epoch": 1203,
        "pubkey": "0x42f87bc7c8fa10408425bbeeeb3dc3874242b4bd92f57775b60b39142426f9ec80b273a64269332d97bdb7d93ae05a42",
        "validator_index": null,
        "vote": null
    }
]
```
