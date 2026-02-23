# beacon_chain crate

The core consensus engine. Orchestrates state transitions, block verification, attestations, and fork choice.

## Critical: Lock Ordering

`BeaconChain<T>` has **29+ RwLock/Mutex fields**. The `canonical_head` module uses a 3-lock system:

1. `RwLock<BeaconForkChoice>` — proto-array fork choice
2. `RwLock<CachedHead>` — cached block/state from last head computation
3. `Mutex<()>` — prevents concurrent `recompute_head`

**Rules** (see `src/canonical_head.rs:9-32`):
- Never expose `RwLockWriteGuard` or `RwLockReadGuard` publicly — only return data
- This prevents external code from acquiring locks in conflicting orders
- Any lock changes need deadlock review

## Critical: Async Safety

Never block the async runtime:
```rust
// WRONG
async fn process() { expensive_work(); }

// RIGHT
async fn process() {
    self.spawn_blocking_handle(|| expensive_work(), "task-name").await?;
}
```

Use `BeaconChain::spawn_blocking_handle()` or `spawn_blocking_with_rayon_async()` — not `tokio::task::spawn_blocking` directly.

## Key Files

| File | Size | Purpose |
|---|---|---|
| `beacon_chain.rs` | 310KB | Main `BeaconChain<T>` struct and state machine |
| `canonical_head.rs` | 61KB | Head management, lock ordering docs |
| `block_verification.rs` | 86KB | Multi-stage block validation pipeline |
| `attestation_verification.rs` | 61KB | Attestation validation |
| `validator_monitor.rs` | 82KB | Validator performance tracking |
| `test_utils.rs` | 127KB | `BeaconChainHarness` for testing |

## Testing

```bash
# Default (electra fork)
FORK_NAME=electra cargo nextest run -p beacon_chain

# Other forks
FORK_NAME=fulu cargo nextest run -p beacon_chain

# Specific test
FORK_NAME=electra cargo nextest run -p beacon_chain <test_name>
```

Requires `fork_from_env` feature (enabled by default in test config).
