# Late Block Re-orgs

Since v3.4.0 Lighthouse will opportunistically re-org late blocks when proposing.

This feature is intended to disincentivise late blocks and improve network health. Proposing a
re-orging block is also more profitable for the proposer because it increases the number of
attestations and transactions that can be included.

## Command line flags

There are three flags which control the re-orging behaviour:

* `--disable-proposer-reorgs`: turn re-orging off (it's on by default).
* `--proposer-reorg-threshold N`: attempt to orphan blocks with less than N% of the committee vote. If this parameter isn't set then N defaults to 20% when the feature is enabled.
* `--proposer-reorg-epochs-since-finalization N`: only attempt to re-org late blocks when the number of epochs since finalization is less than or equal to N. The default is 2 epochs,
  meaning re-orgs will only be attempted when the chain is finalizing optimally.
* `--proposer-reorg-cutoff T`: only attempt to re-org late blocks when the proposal is being made
  before T milliseconds into the slot. Delays between the validator client and the beacon node can
  cause some blocks to be requested later than the start of the slot, which makes them more likely
  to fail. The default cutoff is 1000ms on mainnet, which gives blocks 3000ms to be signed and
  propagated before the attestation deadline at 4000ms.
* `--proposer-reorg-disallowed-offsets N1,N2,N3...`: Prohibit Lighthouse from attempting to reorg at
  specific offsets in each epoch. A disallowed offset `N` prevents reorging blocks from being
  proposed at any `slot` such that `slot % SLOTS_PER_EPOCH == N`. The value to this flag is a
  comma-separated list of integer offsets.

All flags should be applied to `lighthouse bn`. The default configuration is recommended as it
balances the chance of the re-org succeeding against the chance of failure due to attestations
arriving late and making the re-org block non-viable.

## Safeguards

To prevent excessive re-orgs there are several safeguards in place that limit when a re-org
will be attempted.

The full conditions are described in [the spec][] but the most important ones are:

* Only single-slot re-orgs: Lighthouse will build a block at N + 1 to re-org N by building on the
  parent N - 1. The result is a chain with exactly one skipped slot.
* No epoch boundaries: to ensure that the selected proposer does not change, Lighthouse will
  not propose a re-orging block in the 0th slot of an epoch.

## Logs

You can track the reasons for re-orgs being attempted (or not) via Lighthouse's logs.

A pair of messages at `INFO` level will be logged if a re-org opportunity is detected:

> INFO Attempting re-org due to weak head      threshold_weight: 45455983852725, head_weight: 0, parent: 0x09d953b69041f280758400c671130d174113bbf57c2d26553a77fb514cad4890, weak_head: 0xf64f8e5ed617dc18c1e759dab5d008369767c3678416dac2fe1d389562842b49

> INFO Proposing block to re-org current head  head_to_reorg: 0xf64f…2b49, slot: 1105320

This should be followed shortly after by a `WARN` log indicating that a re-org occurred. This is
expected and normal:

> WARN Beacon chain re-org                     reorg_distance: 1, new_slot: 1105320, new_head: 0x72791549e4ca792f91053bc7cf1e55c6fbe745f78ce7a16fc3acb6f09161becd, previous_slot: 1105319, previous_head: 0xf64f8e5ed617dc18c1e759dab5d008369767c3678416dac2fe1d389562842b49

In case a re-org is not viable (which should be most of the time), Lighthouse will just propose a
block as normal and log the reason the re-org was not attempted at debug level:

> DEBG Not attempting re-org                   reason: head not late

If you are interested in digging into the timing of `forkchoiceUpdated` messages sent to the
execution layer, there is also a debug log for the suppression of `forkchoiceUpdated` messages
when Lighthouse thinks that a re-org is likely:

> DEBG Fork choice update overridden           slot: 1105320, override: 0x09d953b69041f280758400c671130d174113bbf57c2d26553a77fb514cad4890, canonical_head: 0xf64f8e5ed617dc18c1e759dab5d008369767c3678416dac2fe1d389562842b49

[the spec]: https://github.com/ethereum/consensus-specs/pull/3034
