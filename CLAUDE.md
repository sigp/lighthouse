# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

**Important**: Always branch from `unstable` and target `unstable` when creating pull requests.

### Building and Installation

- `make install` - Build and install the main Lighthouse binary in release mode
- `make install-lcli` - Build and install the `lcli` utility binary
- `cargo build --release` - Standard Rust release build
- `cargo build --bin lighthouse --features "gnosis,slasher-lmdb"` - Build with specific features

### Testing

- `make test` - Run the full test suite in release mode (excludes EF tests, beacon_chain, slasher, network, http_api)
- `make test-release` - Run tests using nextest (faster parallel test runner)
- `make test-beacon-chain` - Run beacon chain tests for all supported forks
- `make test-slasher` - Run slasher tests with all database backend combinations
- `make test-ef` - Download and run Ethereum Foundation test vectors
- `make test-full` - Complete test suite including linting, EF tests, and execution engine tests
- `cargo nextest run -p <package_name>` - Run tests for a specific package
- `cargo nextest run -p <package_name> <test_name>` - Run individual test (preferred during development iteration)
- `FORK_NAME=electra cargo nextest run -p beacon_chain` - Run tests for specific fork

**Note**: Full test suite takes ~20 minutes. When iterating, prefer running individual tests.

### Linting and Code Quality

- `make lint` - Run Clippy linter with project-specific rules
- `make lint-full` - Run comprehensive linting including tests (recommended for thorough checking)
- `make cargo-fmt` - Check code formatting with rustfmt
- `make check-benches` - Typecheck benchmark code
- `make audit` - Run security audit on dependencies

### Cross-compilation

- `make build-x86_64` - Cross-compile for x86_64 Linux
- `make build-aarch64` - Cross-compile for ARM64 Linux
- `make build-riscv64` - Cross-compile for RISC-V 64-bit Linux

## Architecture Overview

Lighthouse is a modular Ethereum consensus client with two main components:

### Core Components

**Beacon Node** (`beacon_node/`)

- Main consensus client that syncs with the Ethereum network
- Contains the beacon chain state transition logic (`beacon_node/beacon_chain/`)
- Handles networking, storage, and P2P communication
- Provides HTTP API for validator clients and external tools
- Entry point: `beacon_node/src/lib.rs`

**Validator Client** (`validator_client/`)

- Manages validator keystores and performs validator duties
- Connects to beacon nodes via HTTP API
- Handles block proposals, attestations, and sync committee duties
- Includes slashing protection and doppelganger detection
- Entry point: `validator_client/src/lib.rs`

### Key Subsystems

**Consensus Types** (`consensus/types/`)

- Core Ethereum consensus data structures (BeaconState, BeaconBlock, etc.)
- Ethereum specification implementations for different networks (mainnet, gnosis)
- SSZ encoding/decoding and state transition primitives

**Storage** (`beacon_node/store/`)

- Hot/cold database architecture for efficient beacon chain storage
- Supports multiple backends (LevelDB, RocksDB, REDB)
- Handles state pruning and historical data management

**Networking** (`beacon_node/lighthouse_network/`, `beacon_node/network/`)

- Libp2p-based P2P networking stack
- Gossipsub for message propagation
- Discovery v5 for peer discovery
- Request/response protocols for sync

**Fork Choice** (`consensus/fork_choice/`, `consensus/proto_array/`)

- Implements Ethereum's fork choice algorithm (proto-array)
- Manages chain reorganizations and finality

**Execution Layer Integration** (`beacon_node/execution_layer/`)

- Interfaces with execution clients
- Retrieves payloads from local execution layer or external block builders
- Handles payload validation and builder integration

**Slasher** (`slasher/`)

- Optional slashing detection service
- Supports LMDB, MDBX, and REDB database backends
- Can be enabled with `--slasher` flag

### Utilities

**Account Manager** (`account_manager/`) - CLI tool for managing validator accounts and keystores
**LCLI** (`lcli/`) - Lighthouse command-line utilities for debugging and testing
**Database Manager** (`database_manager/`) - Database maintenance and migration tools

### Build System Notes

- Uses Cargo workspace with 90+ member crates
- Supports multiple Ethereum specifications via feature flags (`gnosis`, `spec-minimal`)
- Cross-compilation support for Linux x86_64, ARM64, and RISC-V
- Multiple build profiles: `release`, `maxperf`, `reproducible`
- Feature-based compilation for different database backends and optional components

### Network Support

- **Mainnet**: Default production network
- **Gnosis**: Alternative network (requires `gnosis` feature)
- **Testnets**: Holesky, Sepolia via built-in network configs
- **Custom networks**: Via `--testnet-dir` flag

### Key Configuration

- Default data directory: `~/.lighthouse/{network}`
- Beacon node data: `~/.lighthouse/{network}/beacon`
- Validator data: `~/.lighthouse/{network}/validators`
- Configuration primarily via CLI flags and YAML files

## Common Review Standards

### CI/Testing Requirements

- All checks must pass before merge
- Test coverage expected for significant changes
- Flaky tests are actively addressed and fixed
- New features often require corresponding tests
- `beacon_chain` and `http_api` tests support fork-specific testing using `FORK_NAME` env var when `beacon_chain/fork_from_env` feature is enabled

### Code Quality Standards

- Clippy warnings must be fixed promptly (multiple PRs show this pattern)
- Code formatting with `cargo fmt` enforced
- Must run `cargo sort` when adding dependencies - dependency order is enforced on CI
- Performance considerations for hot paths

### Documentation and Context

- PRs require clear descriptions of what and why
- Breaking changes need migration documentation
- API changes require documentation updates
- When CLI is updated, run `make cli-local` to generate updated help text in lighthouse book
- Comments appreciated for complex logic

### Security and Safety

- Careful review of consensus-critical code paths
- Error handling patterns must be comprehensive
- Input validation for external data

## Development Patterns and Best Practices

### Panics and Error Handling

- **Panics should be avoided at all costs**
- Always prefer returning a `Result` or `Option` over causing a panic (e.g., prefer `array.get(1)?` over `array[1]`)
- Avoid `expect` or `unwrap` at runtime - only acceptable during startup when validating CLI flags or configurations
- If you must make assumptions about panics, use `.expect("Helpful message")` instead of `.unwrap()` and provide detailed reasoning in nearby comments
- Use proper error handling with `Result` types and graceful error propagation

### Rayon Usage

- Avoid using the rayon global thread pool as it results in CPU oversubscription when the beacon processor has fully allocated all CPUs to workers
- Use scoped rayon pools started by beacon processor for computational intensive tasks

### Locks

- Take great care to avoid deadlocks when working with fork choice locks - seek detailed review ([reference](beacon_node/beacon_chain/src/canonical_head.rs:9))
- Keep lock scopes as narrow as possible to avoid blocking fast-responding functions like the networking stack

### Async Patterns

- Avoid blocking computations in async tasks
- Spawn a blocking task instead for CPU-intensive work

### Tracing

- Design spans carefully and avoid overuse of spans just to add context data to events
- Avoid using spans on simple getter methods as it can result in performance overhead
- Be cautious of span explosion with recursive functions
- Use spans per meaningful step or computationally critical step
- Avoid using `span.enter()` or `span.entered()` in async tasks

### Database

- Maintain schema continuity on `unstable` branch
- Database migrations must be backward compatible

### Consensus Crate

- Use safe math methods like `saturating_xxx` or `checked_xxx`
- Critical that this crate behaves deterministically and MUST not have undefined behavior

### Testing Patterns

- **Use appropriate test types for the right scenarios**:
  - **Unit tests** for single component edge cases and isolated logic
  - **Integration tests** using [`BeaconChainHarness`](beacon_node/beacon_chain/src/test_utils.rs:668) for end-to-end workflows
- **`BeaconChainHarness` guidelines**:
  - Excellent for integration testing but slower than unit tests
  - Prefer unit tests instead for testing edge cases of single components
  - Reserve for testing component interactions and full workflows
- **Mocking strategies**:
  - Use `mockall` crate for unit test mocking
  - Use `mockito` for HTTP API mocking (see [`validator_test_rig`](testing/validator_test_rig/src/mock_beacon_node.rs:20) for examples)
- **Event-based testing for sync components**:
  - Use [`TestRig`](beacon_node/network/src/sync/tests/mod.rs) pattern for testing sync components
  - Sync components interact with the network and beacon chain via events (their public API), making event-based testing more suitable than using internal functions and mutating internal states
  - Enables testing of complex state transitions and timing-sensitive scenarios
- **Testing `BeaconChain` dependent components**:
  - `BeaconChain` is difficult to create for TDD
  - Create intermediate adapter structs to enable easy mocking
  - See [`beacon_node/beacon_chain/src/fetch_blobs/tests.rs`](beacon_node/beacon_chain/src/fetch_blobs/tests.rs) for the adapter pattern
- **Local testnet for manual/full E2E testing**:
  - Use Kurtosis-based local testnet setup for comprehensive testing
  - See [`scripts/local_testnet/README.md`](scripts/local_testnet/README.md) for setup instructions

### TODOs and Comments

- All `TODO` statements must be accompanied by a GitHub issue link
- Prefer line (`//`) comments to block comments (`/* ... */`)
- Use doc comments (`///`) before attributes for public items
- Keep documentation concise and clear - avoid verbose explanations
- Provide examples in doc comments for public APIs when helpful

## Logging Guidelines

Use appropriate log levels for different scenarios:

- **`crit`**: Critical issues with major impact to Lighthouse functionality - Lighthouse may not function correctly without resolving. Needs immediate attention.
- **`error`**: Error cases that may have moderate impact to Lighthouse functionality. Expect to receive reports from users for this level.
- **`warn`**: Unexpected code paths that don't have major impact - fully recoverable. Expect user reports if excessive warning logs occur.
- **`info`**: High-level logs indicating beacon node status and block import status. Should not be used excessively.
- **`debug`**: Events lower level than info useful for developers. Can also log errors expected during normal operation that users don't need to action.

## Code Examples

### Safe Math in Consensus Crate

```rust
// ❌ Avoid - could panic
let result = a + b;

// ✅ Preferred
let result = a.saturating_add(b);
// or
use safe_arith::SafeArith;

let result = a.safe_add(b)?;
```

### Panics and Error Handling

```rust
// ❌ Avoid - could panic at runtime
let value = some_result.unwrap();
let item = array[1];

// ✅ Preferred - proper error handling
let value = some_result.map_err(|e| CustomError::SomeVariant(e))?;
let item = array.get(1)?;

// ✅ Acceptable during startup for CLI/config validation
let config_value = matches.get_one::<String>("required-flag")
    .expect("Required flag must be present due to clap validation");

// ✅ If you must make runtime assumptions, use expect with explanation
let item = array.get(1).expect("Array always has at least 2 elements due to validation in constructor");
// Detailed reasoning should be provided in nearby comments
```

### TODO Format

```rust
pub fn my_function(&mut self, _something: &[u8]) -> Result<String, Error> {
    // TODO: Implement proper validation here
    // https://github.com/sigp/lighthouse/issues/1234
}
```

### Async Task Spawning for Blocking Work

```rust
// ❌ Avoid - blocking in async context
async fn some_handler() {
    let result = expensive_computation(); // blocks async runtime
}

// ✅ Preferred
async fn some_handler() {
    let result = tokio::task::spawn_blocking(|| {
        expensive_computation()
    }).await?;
}
```

### Tracing Span Usage

```rust
// ❌ Avoid - span on simple getter
#[instrument]
fn get_head_block_root(&self) -> Hash256 {
    self.head_block_root
}

// ✅ Preferred - span on meaningful operations
#[instrument(skip(self))]
async fn process_block(&self, block: Block) -> Result<(), Error> {
    // meaningful computation
}
```

## Build and Development Notes

- Full builds and tests take 5+ minutes - use large timeouts (300s+) for any `cargo build`, `cargo nextest`, or `make` commands
- Use `cargo check` for faster iteration during development and always run after code changes
- Prefer targeted package tests (`cargo nextest run -p <package>`) and individual tests over full test suite when debugging specific issues
- Use `cargo fmt --all && make lint-fix` to format code and fix linting issues once a task is complete
- Always understand the broader codebase patterns before making changes
- Minimum Supported Rust Version (MSRV) is documented in `lighthouse/Cargo.toml` - ensure Rust version meets or exceeds this requirement
