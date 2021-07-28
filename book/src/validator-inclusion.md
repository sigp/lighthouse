# Validator Inclusion APIs

The `/lighthouse/validator_inclusion` API endpoints provide information on
results of the proof-of-stake voting process used for finality/justification
under Casper FFG.

These endpoints are not stable or included in the Eth2 standard API. As such,
they are subject to change or removal without a change in major release
version.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/lighthouse/validator_inclusion/{epoch}/global`](#global) | A global vote count for a given epoch.
[`/lighthouse/validator_inclusion/{epoch}/{validator_id}`](#individual) | A per-validator breakdown of votes in a given epoch.

## Global

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
- `current_epoch_target_attesting_gwei`: the total staked gwei that attested to
	the majority-elected Casper FFG target epoch during the current epoch.
- `previous_epoch_active_gwei`: as per `current_epoch_active_gwei`, but during the previous epoch.
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

### HTTP Example

```bash
curl -X GET "http://localhost:5052/lighthouse/validator_inclusion/0/global" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "current_epoch_active_gwei": 642688000000000,
    "previous_epoch_active_gwei": 642688000000000,
    "current_epoch_target_attesting_gwei": 366208000000000,
    "previous_epoch_target_attesting_gwei": 1000000000,
    "previous_epoch_head_attesting_gwei": 1000000000
  }
}
```

## Individual

Returns a per-validator summary of how that validator performed during the
current epoch.

The [Global Votes](#consensusglobal_votes) endpoint is the summation of all of these
individual values, please see it for definitions of terms like "current_epoch",
"previous_epoch" and "target_attester".


### HTTP Example

```bash
curl -X GET "http://localhost:5052/lighthouse/validator_inclusion/0/42" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "is_slashed": false,
    "is_withdrawable_in_current_epoch": false,
    "is_active_unslashed_in_current_epoch": true,
    "is_active_unslashed_in_previous_epoch": true,
    "current_epoch_effective_balance_gwei": 32000000000,
    "is_current_epoch_target_attester": false,
    "is_previous_epoch_target_attester": false,
    "is_previous_epoch_head_attester": false
  }
}
```
