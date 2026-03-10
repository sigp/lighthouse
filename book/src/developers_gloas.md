# Gloas

The Gloas hard fork adds proposer builder separation (ePBS) to Ethereum, with profound implications
for Lighthouse's implementation. This document serves as a reference for Lighthouse developers
during Gloas development, and a central hub for Gloas knowledge and design decisions.

## Terminology

### Payload statuses

We use the following terms to refer to **slots** and **states** depending on whether they have had a
block or a payload envelope applied most recently.

- **Full**: A full state or slot is one which has had a **payload envelope** applied using
  `process_execution_payload_envelope` most recently (NOT a `BeaconBlock`).
- **Pending**: A pending state or slot is one which has had **`BeaconBlock`** applied using
  `per_block_processing` most recently (NOT an `ExecutionPayloadEnvelope`).
- **Empty**: A slot with no payload envelope. States **cannot be empty**, because the state
  corresponding to an empty slot is just the `Pending` state. A slot is empty within the context of
  a specific chain if there is a block at that slot, but the payload envelope at that slot is not
  part of that chain.

We continue to use the term **skipped** to refer to slots with no `BeaconBlock`. It is important not
to confuse empty/skipped terminology when referring to states. E.g. it is possible for a skipped slot
**state** to be full. A state at slot 6 is skipped and full if there is a block at slot 5, a
payload at slot 5, and nothing at slot 6.

### Parent block

Avoid using _parent block_ to refer to the same-slot beacon block associated with a payload
envelope. Prefer to say _same-slot block_, or _payload's block_ for clarity. This avoids confusion
with the parent block of the beacon block.

- **Parent block**: the previous `BeaconBlock` of a block, as determined by `parent_root`.
- **Same-slot block**: for a payload, the `BeaconBlock` containing the bid that commits to that
  payload.

## Assumptions and Invariants

## Shuffling equivalence

In several places we assume that the `Pending` and `Full` states at the end of epoch `N` produce the
same shufflings at epoch `N` and `N + 1`, i.e. that the same dependent block root used prior to
Gloas continues to be sufficient to uniquely define a shuffling.

This is true in current versions of the spec, but this assumption may need to be revisited if there
are substantial changes to epoch processing.

Further reasoning about this [here](https://hackmd.io/@dapplion/gloas_dependant_root).
