# store crate

Persistent storage with hot/cold split. All beacon state, blocks, and blobs are stored here.

## Architecture: Hot/Cold Split

- **Hot DB**: Recent data (~27 hours). Stores **diffs**, not full states. Fast access.
- **Cold DB**: Finalized data. Stores snapshots + diffs at epoch boundaries.
- **Migration**: Happens automatically at finalization boundaries.

Full states in hot DB are **deprecated** — use `BeaconStateHotDiff` for compact storage.

## Critical: Atomic Operations

Multi-key writes must be atomic to prevent corruption:

```rust
// ALWAYS use do_atomically for multi-key updates
store.do_atomically(vec![
    StoreOp::PutBlock(block_root, Arc::new(block)),
    StoreOp::PutState(state_root, &state),
    StoreOp::PutPayload(block_root, payload),
])?;
```

Never write related keys in separate operations — partial writes on failure corrupt the database.

## Critical: DBColumn Selection

Each data type maps to a specific `DBColumn` variant. **Wrong column = data loss or silent corruption.**

Key columns:
- `BeaconBlock` — signed beacon blocks
- `BeaconStateHotDiff` — hot state diffs (replaces deprecated `BeaconState`)
- `BeaconStateDiff` — cold state diffs
- `ExecPayload` — execution payloads
- `ForkChoice` — persisted fork choice

## Schema Migrations

- Schema version tracked in metadata (`SchemaVersion`)
- Migrations run on startup
- Adding new columns or changing key formats requires a migration
- Test migrations with both upgrade and downgrade paths

## Key Files

| File | Purpose |
|---|---|
| `hot_cold_store.rs` (159KB) | Main `HotColdDB` implementation |
| `state_cache.rs` | In-memory state cache |
| `hdiff.rs` | Hot state diff computation |
| `reconstruct.rs` | Reconstruct full states from diffs |
| `metadata.rs` | Schema versions, anchor info |

## Testing

```bash
cargo nextest run -p store
```
