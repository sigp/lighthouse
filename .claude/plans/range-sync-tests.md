# Goal: Range Sync Test Coverage

## What

Add comprehensive test coverage for Lighthouse range sync (`BlocksByRange`, `BlobsByRange`, `DataColumnsByRange`).

## How

Tests MUST follow the exact pattern from `lookups.rs`:

```rust
async fn test_name() {
    let mut r = TestRig::default();
    r.setup_xyz().await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
}
```

### Rules

1. **Tests must be succinct and readable** — 3-10 lines per test body max
2. **All complex logic lives in helpers** — setup helpers, SimulateConfig extensions, assert helpers
3. **Test bodies MUST NOT**: call `find_and_complete_blocks_by_range_request`, send `SyncMessage` directly, or do anything overly specific
4. **All tests use `simulate()`** if they need peers to fulfill requests
5. **Extend `SimulateConfig`** for new range-specific behaviors
6. **Extend `simulate()`** to support by_range methods

---

## Existing Tests — Analysis & Migration Plan

### 1. `head_chain_removed_while_finalized_syncing` (regression #2821)

**What it does:** Add head peer → head chain created → grab head batch request → add finalized peer → finalized chain takes priority → grab finalized batch request → disconnect head peer → assert still in Finalized state.

**What it tests:** When a head chain exists and a finalized peer arrives, the finalized chain takes priority. Disconnecting the head peer removes the head chain but the finalized chain survives.

**Migration:** Already covered by `finalized_to_head_transition` (finalized takes priority, both complete). But the specific "head peer disconnect during finalized sync" scenario is NOT tested. Add:
```rust
async fn head_peer_disconnect_during_finalized_sync() {
    let mut r = TestRig::default();
    r.setup_finalized_and_head_sync().await;
    // disconnect head peer, finalized sync should still complete
    r.simulate(SimulateConfig::happy_path().with_disconnect_head_peers()).await;
    r.assert_range_sync_completed();
}
```
**Needs:** `SimulateConfig::with_disconnect_head_peers()` — disconnect head peers mid-simulate but keep finalized peers.

### 2. `state_update_while_purging` (regression #2827)

**What it tested:** When chain targets become known to fork choice during a state update, `purge_outdated_chains` runs before `update_finalized_chains`/`update_head_chains` without crashing.

**Removed:** The bug was a call ordering issue in `ChainCollection::update()`. The fix hardcodes `purge_outdated_chains` (line 223) before `update_finalized_chains` (line 227) and `update_head_chains` (line 231) in a single function body. This ordering can't regress without visibly rewriting `update()`.

### 3. `pause_and_resume_on_ee_offline`

**What it does:** Add head peer → EE goes offline → complete head batch → processor empty (paused) → add finalized peer → complete finalized batch → processor still empty → EE back online → assert 2 chain segments in processor queue.

**What it tests:** When the execution engine goes offline, completed batches queue up and aren't sent to the processor. When EE comes back online, all queued batches are dispatched.

**Migration:**
```rust
async fn pause_and_resume_on_ee_offline() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_ee_offline_for_n_batches(2)).await;
    r.assert_range_sync_completed();
}
```
**Needs:** `SimulateConfig::with_ee_offline_for_n_batches(n)` — set EE offline before simulate, toggle back online after N batches complete. The simulate loop would need to call `update_execution_engine_state` at the right time.

### 4. `finalized_sync_enough_global_custody_peers_few_chain_peers`

**What it does:** Add 100 fullnode peers + 1 supernode → assert finalized state → drive sync to completion via `complete_and_process_range_sync_until`.

**What it tests:** End-to-end finalized sync with sufficient custody column coverage across many peers. Tests that range sync can complete when no single peer has all columns but the swarm collectively covers them.

**Migration:** ✅ **Already covered by `finalized_sync_completes`** — uses `setup_finalized_sync()` which adds 100 fullnode peers + 1 supernode, builds a real chain, and `simulate()` drives it to completion with `assert_range_sync_completed()`.

### 5. `finalized_sync_not_enough_custody_peers_on_start` (PeerDAS-only)

**What it does:** Add single fullnode → assert finalized state → assert no network requests (not enough custody coverage) → add 100 fullnodes + 1 supernode → drive sync to completion.

**What it tests:** When there aren't enough peers to cover all custody columns, range sync creates the chain but doesn't send requests. Once enough peers arrive, sync proceeds.

**Migration:**
```rust
async fn finalized_sync_not_enough_custody_peers_on_start() {
    let mut r = TestRig::default();
    r.setup_finalized_sync_with_insufficient_peers().await;
    r.assert_empty_network(); // no requests sent yet
    r.add_sufficient_peers().await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
}
```
**Needs:** `setup_finalized_sync_with_insufficient_peers()` — adds only 1 fullnode peer. `add_sufficient_peers()` — adds 100 fullnodes + 1 supernode. This is PeerDAS-only so needs a `if !fulu_enabled() { return; }` guard.

---

## New Tests — Current Coverage

| Test | What it covers | SimulateConfig |
|------|---------------|----------------|
| `head_sync_completes` | Head sync happy path, all blocks ingested | `happy_path()` |
| `finalized_sync_completes` | Finalized sync happy path, all blocks ingested, finalized epoch advances | `happy_path()` |
| `finalized_to_head_transition` | Finalized completes → head chain drains | `happy_path()` |
| `batch_rpc_error_retries` | RPC error → retry → completes, no penalties | `return_rpc_error()` |
| `batch_peer_returns_empty_then_succeeds` | Empty BlocksByRange response → retry | `with_no_range_blocks_n_times(1)` |
| `batch_peer_returns_no_columns_then_succeeds` | Empty DataColumnsByRange → retry | `with_no_range_columns_n_times(1)` |
| `batch_peer_returns_wrong_column_indices_then_succeeds` | Unrequested column indices → `UnrequestedIndex` | `with_wrong_range_column_indices_n_times(1)` |
| `batch_peer_returns_wrong_column_slots_then_succeeds` | Out-of-range column slot → `UnrequestedSlot` | `with_wrong_range_column_slots_n_times(1)` |
| `batch_non_faulty_failure_retries` | NonFaultyFailure → retry → completes, no penalties | `with_range_non_faulty_failures(1)` |
| `batch_faulty_failure_redownloads` | FaultyFailure → redownload → completes, `faulty_batch` penalty | `with_range_faulty_failures(1)` |
| `batch_max_failures_removes_chain` | 3x FaultyFailure → chain removed, `faulty_chain` penalty | `with_range_faulty_failures(3)` |
| `failed_chain_blacklisted` | Chain fails → root blacklisted → new peer with same root gets Goodbye | `with_range_faulty_failures(3)` |
| `all_peers_disconnect_removes_chain` | All peers disconnect → chain removed | `with_disconnect_after_range_requests(0)` |
| `late_response_for_removed_chain` | Response arrives after chain removed → no-op | `with_disconnect_after_range_requests(1)` |

## Files

- `beacon_node/network/src/sync/tests/range.rs` — range sync tests
- `beacon_node/network/src/sync/tests/lookups.rs` — shared `SimulateConfig` + `simulate()` + helpers
