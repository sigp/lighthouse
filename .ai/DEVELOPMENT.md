# Lighthouse Development Guide

Development patterns, commands, and architecture for AI assistants and contributors.

## Development Commands

**Important**: Always branch from `unstable` and target `unstable` when creating pull requests.

### Building

- `make install` - Build and install Lighthouse in release mode
- `make install-lcli` - Build and install `lcli` utility
- `cargo build --release` - Standard release build
- `cargo build --bin lighthouse --features "gnosis,slasher-lmdb"` - Build with specific features

### Testing

- `make test` - Full test suite in release mode
- `make test-release` - Run tests using nextest (faster parallel runner)
- `cargo nextest run -p <package>` - Run tests for specific package (preferred for iteration)
- `cargo nextest run -p <package> <test_name>` - Run individual test
- `FORK_NAME=electra cargo nextest run -p beacon_chain` - Run tests for specific fork
- `make test-ef` - Ethereum Foundation test vectors

**Fork-specific testing**: `beacon_chain` and `http_api` tests support fork-specific testing via `FORK_NAME` env var when `beacon_chain/fork_from_env` feature is enabled.

**Note**: Full test suite takes ~20 minutes. Prefer targeted tests when iterating.

### Linting

- `make lint` - Run Clippy with project rules
- `make lint-full` - Comprehensive linting including tests
- `cargo fmt --all && make lint-fix` - Format and fix linting issues
- `cargo sort` - Sort dependencies (enforced on CI)

## Architecture Overview

Lighthouse is a modular Ethereum consensus client with two main components:

### Beacon Node (`beacon_node/`)

- Main consensus client syncing with Ethereum network
- Beacon chain state transition logic (`beacon_node/beacon_chain/`)
- Networking, storage, P2P communication
- HTTP API for validator clients
- Entry point: `beacon_node/src/lib.rs`

### Validator Client (`validator_client/`)

- Manages validator keystores and duties
- Block proposals, attestations, sync committee duties
- Slashing protection and doppelganger detection
- Entry point: `validator_client/src/lib.rs`

### Key Subsystems

| Subsystem | Location | Purpose |
|-----------|----------|---------|
| Consensus Types | `consensus/types/` | Core data structures, SSZ encoding |
| Storage | `beacon_node/store/` | Hot/cold database (LevelDB, RocksDB, REDB backends) |
| Networking | `beacon_node/lighthouse_network/` | Libp2p, gossipsub, discovery |
| Fork Choice | `consensus/fork_choice/` | Proto-array fork choice |
| Execution Layer | `beacon_node/execution_layer/` | EL client integration |
| Slasher | `slasher/` | Optional slashing detection |

### Utilities

- `account_manager/` - Validator account management
- `lcli/` - Command-line debugging utilities
- `database_manager/` - Database maintenance tools

## Code Quality Standards

### Panic Avoidance (Critical)

**Panics should be avoided at all costs.**

```rust
// NEVER at runtime
let value = some_result.unwrap();
let item = array[1];

// ALWAYS prefer
let value = some_result?;
let item = array.get(1)?;

// Only acceptable during startup
let config = matches.get_one::<String>("flag")
    .expect("Required due to clap validation");
```

### Consensus Crate Safety (`consensus/` excluding `types/`)

Extra scrutiny required - bugs here cause consensus failures.

```rust
// NEVER standard arithmetic
let result = a + b;

// ALWAYS safe math
let result = a.saturating_add(b);
// or
use safe_arith::SafeArith;
let result = a.safe_add(b)?;
```

Requirements:
- Use `saturating_*` or `checked_*` operations
- Zero panics - no `.unwrap()`, `.expect()`, or `array[i]`
- Deterministic behavior across all platforms

### Error Handling

- Return `Result` or `Option` instead of panicking
- Log errors, don't silently swallow them
- Provide context with errors

### Async Patterns

```rust
// NEVER block in async context
async fn handler() {
    expensive_computation(); // blocks runtime
}

// ALWAYS spawn blocking
async fn handler() {
    tokio::task::spawn_blocking(|| expensive_computation()).await?;
}
```

### Concurrency

- **Lock ordering**: Document lock ordering to avoid deadlocks. See [`canonical_head.rs:9-32`](beacon_node/beacon_chain/src/canonical_head.rs) for excellent example documenting three locks and safe acquisition order.
- Keep lock scopes narrow
- Seek detailed review for lock-related changes

### Rayon Thread Pools

Avoid using the rayon global thread pool - it causes CPU oversubscription when beacon processor has fully allocated all CPUs to workers. Use scoped rayon pools started by beacon processor for computationally intensive tasks.

### Tracing Spans

- Avoid spans on simple getter methods (performance overhead)
- Be cautious of span explosion with recursive functions
- Use spans per meaningful computation step, not every function
- **Never** use `span.enter()` or `span.entered()` in async tasks

### Documentation

- All `TODO` comments must link to a GitHub issue
- Prefer line comments (`//`) over block comments
- Keep comments concise, explain "why" not "what"

## Logging Levels

| Level | Use Case |
|-------|----------|
| `crit` | Lighthouse may not function - needs immediate attention |
| `error` | Moderate impact - expect user reports |
| `warn` | Unexpected but recoverable |
| `info` | High-level status - not excessive |
| `debug` | Developer events, expected errors |

## Testing Patterns

- **Unit tests**: Single component edge cases
- **Integration tests**: Use [`BeaconChainHarness`](beacon_node/beacon_chain/src/test_utils.rs) for end-to-end workflows
- **Sync components**: Use [`TestRig`](beacon_node/network/src/sync/tests/mod.rs) pattern with event-based testing
- **Mocking**: `mockall` for unit tests, `mockito` for HTTP APIs
- **Adapter pattern**: For testing `BeaconChain` dependent components, create adapter structs. See [`fetch_blobs/tests.rs`](beacon_node/beacon_chain/src/fetch_blobs/tests.rs)
- **Local testnet**: See `scripts/local_testnet/README.md`

## Build Notes

- Full builds take 5+ minutes - use large timeouts (300s+)
- Use `cargo check` for faster iteration
- MSRV documented in `Cargo.toml`

### Cross-compilation

- `make build-x86_64` - Cross-compile for x86_64 Linux
- `make build-aarch64` - Cross-compile for ARM64 Linux
- `make build-riscv64` - Cross-compile for RISC-V 64-bit Linux

## Parallel Development

For working on multiple branches simultaneously, use git worktrees:

```bash
git worktree add -b my-feature ../lighthouse-my-feature unstable
```

This creates a separate working directory without needing multiple clones. To save disk space across worktrees, configure a shared target directory:

```bash
# In .cargo/config.toml at your workspace root
[build]
target-dir = "/path/to/shared-target"
```
