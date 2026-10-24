# Stale-head advanced state (#9530)

## Problem

When the canonical head stops advancing (e.g. prolonged network outage) but the wall clock keeps moving, validator API handlers that need a state at the current or next epoch clone the **unadvanced head** and run `partial_state_advance` / `per_slot_processing` through every empty epoch since the head. Cost is **O(staleness)**: ~37 ms/epoch on Fulu and ~300 ms/epoch on Gloas at 32k validators in the companion benchmark.

Prior mitigations (`cursor/proposer-duties-next-epoch-cache`, `cursor/attestation-data-stale-head-cache`) cache and single-flight **results**. They remove retry amplification, but the first call each epoch still replays all N empty epochs from the head.

The existing `state_advance_timer` already advances the head by one slot per slot and stores the result via `store.put_state` / the hot state cache. It stops once the head is more than `MAX_ADVANCE_DISTANCE` (256 slots ≈ 8 epochs) behind, to avoid wasted work while syncing or after the node was asleep. Advanced states are also the **first** victims of state-cache cull, so they are not a reliable long-horizon cache. Several HTTP paths also **bypass** `get_advanced_hot_state` and always start from the head snapshot (notably `with_cached_shuffling` when the requested head is the canonical head, and `compute_proposer_duties_from_head`).

## Endpoint investigation

| Endpoint | How state is obtained when head is stale | O(staleness)? | Covered? |
|---|---|---|---|
| `POST .../duties/attester/{epoch}` (current/next) | `with_committee_cache` → `with_cached_shuffling`. For the canonical head it clones the **unadvanced** head snapshot and `partial_state_advance`s to the shuffling target. Shuffling cache single-flights per epoch, but each new epoch still starts from the head. | **Yes** | **Yes** |
| `GET .../duties/proposer/{epoch}` (current/next) | Cache hit is cheap. Miss / next-epoch path uses `compute_proposer_duties_from_head` (or `with_proposer_cache` after the earlier fix), which clones the head and advances to the proposer decision slot. | **Yes** (first miss / new epoch) | **Yes** |
| `POST .../duties/sync/{epoch}` | Prefer `sync_committee_duties_from_head` (reads committees already on the head). Sync periods are 256 epochs on mainnet; typical outages stay inside one period. Slow path loads a **historical** slot (start of previous period) via `state_at_slot`, which does not advance forward from a lagging head. | **No** (for typical staleness) | **No** — already cheap |
| `GET .../attestation_data` | Slow path when `head_epoch != request_epoch`: `get_advanced_hot_state` then `partial_state_advance` to the request epoch. Benefits from any surviving advanced hot state, but after timer stop / cache cull it falls back to the head and costs O(N). | **Yes** | **Yes** |
| `POST .../beacon/states/{slot}/validators` (slot past head) | `StateId::Slot` resolves via `state_root_at_slot`, which has no root for slots after the head → **404** without advancing. Charon falls back to `states/head/validators`. | **No** (fails fast) | **No** — already cheap; head fallback is a clone |
| `GET .../beacon/states/head/validators` | Clones the cached head state. | **No** | **No** |
| `GET .../validator/blocks/{slot}` (block production) | Parent state via `get_advanced_hot_state` + `partial_state_advance` / `complete_state_advance` to the proposal slot. Same O(N) when no advanced state remains. | **Yes** | **Yes** (shared helper) |

HTTP handlers run as blocking tasks on the beacon processor and continue after client disconnect (`http_api/src/task_spawner.rs`), so timeouts from Charon (2s) amplify CPU without cancelling work. That makes incremental advance + single-flight essential, not just result caches.

## Approach

Keep **one** furthest advanced empty-slot state for the current head, and always extend it instead of replaying from the head.

1. **`AdvancedHeadStateCache` on `BeaconChain`**
   - At most **two** retained entries for the current head (bounded memory):
     - **Partial** — `partial_state_advance` (zero intermediate state roots). Fast; suitable for shuffling, duties, attestation justified checkpoints. **Must not** be `put_state`'d (invalid for consensus / block import).
     - **Complete** — `complete_state_advance` (proper state roots). Suitable for block production. Kept **in memory only** on the demand path: `put_state` of a multi-epoch empty-slot jump breaks hierarchical hot diffs (`MissingHotStateSummary`). The state-advance timer still persists one slot at a time and feeds this entry via `observe_complete_advanced_state`.
   - `get_or_advance_to(kind, target_slot)` extends the matching entry under a mutex so concurrent callers share one catch-up.
   - Head change / reorg: `invalidate()` discards both entries.

2. **Route expensive paths through the helper**
   - Attestation production slow path → partial.
   - `with_committee_cache` preloads a partial advanced state into `with_cached_shuffling`.
   - Proposer-duty computation (`compute_proposer_duties_from_head`) → partial.
   - Block production → complete (`head_state_completely_advanced_to`).
   - Prefer this over new per-endpoint result caches; existing proposer / shuffling caches still apply on top.

3. **State advance timer**
   - When the node is **not** long-range syncing (`SyncState` is `Synced` or `Stalled`, or sync status is unavailable), keep advancing past `MAX_ADVANCE_DISTANCE`.
   - While `SyncingFinalized` / `SyncingHead` / `SyncTransition`, keep the existing cap (do not waste work on a head that will be replaced).
   - Each timer tick still advances **one slot** and writes into the store **and** the `AdvancedHeadStateCache`, so HTTP traffic that arrives mid-outage starts near the wall clock.
   - After a long sleep, the first HTTP call may still pay a one-time O(gap) cost; subsequent epochs stay O(1 epoch). The timer then continues catching up one slot per slot.

4. **Memory**
   - Bound retained overhead to **one** extra in-memory state (the cache entry). Intermediate `put_state` results remain subject to normal hot-cache cull; the dedicated entry is not.

## Alternatives considered

| Alternative | Why not (as the primary fix) |
|---|---|
| Only result caches / single-flight (prior branches) | First call per epoch still O(N); cost grows without bound as the outage continues. |
| Raise / remove `MAX_ADVANCE_DISTANCE` alone | Helps while the timer runs, but HTTP paths that clone the head still ignore advanced hot states; cull prefers deleting advanced states; no single-flight for demand path. |
| Advance many slots per timer tick when far behind | Useful catch-up tweak, but without a shared demand-path cache, concurrent HTTP handlers still race from the head. Can be added later on top of this design. |
| Persist a special “stale advanced head” column | Unnecessary: `put_state` already persists; the problem is starting from the wrong state and not retaining one live copy. |
| Refuse validator API while stalled | Rejected earlier for #9538; VCs/Charon need duties during local-only outages. |

## Risks and trade-offs

- **Syncing**: advancing a far-behind head while range-syncing wastes CPU and memory. Mitigated by keeping `MAX_ADVANCE_DISTANCE` whenever sync status says we are long-range syncing.
- **Reorgs**: a new head invalidates the cache by root; brief wasted work on the old root is acceptable.
- **Pre-Fulu next-epoch proposers**: duties still depend on the undecided end of the current epoch. We only advance state for computation; we do **not** claim next-epoch proposer duties are cacheable pre-Fulu (same rule as the earlier proposer-cache fix).
- **Gloas**: epoch processing is heavier; the incremental property matters more. Partial advance + committee/PTC building must still respect Gloas fork-boundary rules already encoded in shuffling / attestation paths.
- **Correctness vs head snapshot**: duties and attestation data must still vote for the real head block root / decision roots. We only reuse empty-slot processing of that same head, never invent blocks.
- **One-time catch-up**: after a multi-hour sleep with no timer progress, the first request remains O(gap). That is inherent; the invariant we guarantee is **per new epoch ≈ one epoch of work** once an advanced state exists near the previous epoch.

## Test plan

- Repro tests (committed first): for each covered endpoint, jump the clock many epochs past the head, then advance epoch-by-epoch. Assert that process_epoch work for the next epoch stays ~1 epoch, not O(N). Also assert single-flight under concurrency and correctness after a new block.
- Companion benchmark branch (not on this candidate): extend `cursor/stale-head-benchmark`, merge into `cursor/stale-head-benchmark-advanced-state`, and record incremental per-epoch cost vs N.
