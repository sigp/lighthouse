# Lighthouse REST API: `/consensus`

## Endpoints

Table of endpoints:

HTTP Path | Description |
| --- | -- |
[`/consensus/vote_count`](#vote-count) | A global vote count for a given epoch.

## Vote Count

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

The votes are expressed in terms of staked `Gwei` (i.e., not the number of
individual validators). For example, if a validator has 32 ETH staked they will
increase the `current_epoch_attesting_gwei` figure by `32,000,000,000` if they
have an attestation included in a block during the current epoch.

The following fields are returned:

- `current_epoch_active_gwei`: the total staked gwei that was active (i.e.,
	able to vote) during the current epoch.
- `previous_epoch_active_gwei`: as above, but during the previous epoch.
- `current_epoch_attesting_gwei`: the total staked gwei that had one or more
    attestations included in a block during the current epoch (multiple
	attestations by the same validator does not increase this figure).
- `current_epoch_target_attesting_gwei`: the total staked gwei that attested to
	the majority-elected Casper FFG target epoch during the current epoch. This
	figure must be equal to or less than `current_epoch_attesting_gwei`.
- `previous_epoch_attesting_gwei`: see `current_epoch_attesting_gwei`.
- `previous_epoch_target_attesting_gwei`: see `current_epoch_target_attesting_gwei`.
- `previous_epoch_head_attesting_gwei`: see `previous_epoch_head_attesting_gwei`.

From this data you can calculate some interesting figures:

### Participation Rate

`previous_epoch_attesting_gwei / previous_epoch_active_gwei`

Expresses the ratio of validators that managed to have an attestation
voting upon the previous epoch included in a block.

### Justification/Finalization Rate

`previous_epoch_target_attesting_gwei / previous_epoch_active_gwei`

When this value is greater than or equal to `2/3` it is possible that the
beacon chain may justify/finalize the previous epoch.


### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/validator/vote_count`
Method | GET
JSON Encoding | Object
Query Parameters | `epoch`
Typical Responses | 200

### Parameters

Requires the `epoch` (`Epoch`) query parameter to determine which epoch will be
considered the current epoch.

### Returns

A set of duties for each given pubkey.

### Example

```json
{
    "current_epoch": 52377600000000,
    "previous_epoch": 52377600000000,
    "current_epoch_attesters": 50740900000000,
    "current_epoch_target_attesters": 49526000000000,
    "previous_epoch_attesters": 52377600000000,
    "previous_epoch_target_attesters": 51063400000000,
    "previous_epoch_head_attesters": 9248600000000
}
```
