# SSZ Proof APIs

These experimental endpoints are provided by Lighthouse. Each returns a single SSZ Merkle
branch. Proof generation runs inside the beacon node and uses its state and cached list trees.
Clients do not need to download or deserialize a full beacon state.

| Endpoint | Purpose |
| --- | --- |
| `GET /lighthouse/beacon/states/{state_id}/proof?gindex={gindex}` | Prove a supported state location |
| `GET /lighthouse/beacon/blocks/{block_id}/proof?gindex={gindex}` | Prove a block location in the outer container |

Each response includes `version`, `execution_optimistic`, `finalized`, and a `data` object with:

- `gindex`: the requested generalized index, encoded as a decimal string.
- `leaf`: the 32-byte leaf or subtree root.
- `witnesses`: sibling hashes ordered from the leaf towards the root.
- `root`: the state root or unsigned beacon block root.

The branch must contain exactly `floor(log2(gindex))` witnesses. Starting from `leaf`, hash the
sibling on the left when the current index is odd and on the right when it is even, then divide
the index by two. The final hash must equal `root`.

## State proofs

For Phase 0 through Fulu, the endpoint supports container nodes, the validator registry and its
record fields, packed balance chunks, and the length mix-in of either list. Four validator
balances share one 32-byte chunk; consumers must extract the appropriate little-endian uint64.
A validator's `pubkey` field is represented by its SSZ root, not by its raw 48-byte value.

An Electra/Fulu balance chunk proof contains 45 witnesses plus its leaf (1,472 raw bytes).
A validator record field proof contains 50 witnesses plus its leaf (1,632 raw bytes). JSON hex
encoding and response metadata add overhead, but neither response includes the full state.

The prototype does not support nested proofs into other state fields or progressive state
layouts (Gloas and Heze). It returns HTTP 400 for these requests instead of interpreting them
with the wrong layout. The state root itself (`gindex=1`) is available for every fork.

For example, prove the first balance chunk in an Electra or Fulu state:

```sh
curl 'http://localhost:5052/lighthouse/beacon/states/finalized/proof?gindex=41781441855488'
```

Historical state requests require the corresponding history to be retained or reconstructible
in the node's database. These endpoints do not backfill missing history or change pruning.
The node may still load or reconstruct the complete requested state internally; the small
proof response does not eliminate historical state loading costs.

## Block proofs

The block endpoint supports nodes in the block's outer container (generalized indices
1 through 15). Generalized index 11 proves `state_root` against the unsigned beacon block root.
It uses a blinded block header and does not rebuild an execution payload from the execution
client. Proofs for fields inside the block body are outside the prototype's scope.

```sh
curl 'http://localhost:5052/lighthouse/beacon/blocks/finalized/proof?gindex=11'
```

## Verification and errors

Use fixed slots or roots for related requests: `head` can change between calls. A validator
proof's state root must equal the chosen block's `state_root`, and the block proof's root must
match the application's authenticated beacon root. A successful API response alone does not
establish that a verifier in a smart contract accepts the anchor.

Malformed or unsupported generalized indices return HTTP 400; unavailable blocks or states
return HTTP 404. Proof work uses the beacon processor's blocking API queue with a lower priority.
