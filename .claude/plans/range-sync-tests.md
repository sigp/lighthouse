# Goal: Range Sync Test Coverage

## What

Add comprehensive test coverage for Lighthouse range sync (`BlocksByRange`, `BlobsByRange`, `DataColumnsByRange`).

## How

Tests MUST follow the exact pattern from `lookups.rs`:

```rust
async fn test_name() {
    let mut r = TestRig::default();
    // SETUP: build chain / add peers in a specific way
    r.setup_xyz();
    // SIMULATE: given some specific behaviour
    r.simulate(SimulateConfig::happy_path()).await;
    // ASSERT: specific outcome
    r.assert_range_sync_completed();
}
```

### Rules

1. **Tests must be succinct and readable** — 3-10 lines per test body max
2. **All complex logic lives in helpers** — setup helpers, SimulateConfig extensions, assert helpers
3. **Test bodies MUST NOT**:
   - Call `find_and_complete_blocks_by_range_request` or similar manual request grabbing
   - Send `SyncMessage` directly
   - Do anything overly specific or manual
4. **All tests use `simulate()`** if they need peers to fulfill requests
5. **Extend `SimulateConfig`** for new range-specific behaviors (failure injection, peer disconnection, etc.)
6. **Extend `simulate()`** to support by_range methods (already done — handles `BlocksByRange`, `BlobsByRange`, `DataColumnsByRange`)

### Pattern Reference (from lookups.rs)

```rust
async fn happy_path_unknown_attestation(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();
}
```

## Test Categories

See `RANGE_SYNC_TESTS.md` for full coverage analysis and proposed tests.

## Files

- `beacon_node/network/src/sync/tests/range.rs` — range sync tests
- `beacon_node/network/src/sync/tests/lookups.rs` — shared `SimulateConfig` + `simulate()` + helpers
- `RANGE_SYNC_TESTS.md` — detailed coverage analysis and test plan
