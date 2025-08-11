# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Installation
- `make install` - Build and install the main Lighthouse binary in release mode
- `make install-lcli` - Build and install the `lcli` utility binary
- `cargo build --release` - Standard Rust release build
- `cargo build --bin lighthouse --features "gnosis,slasher-lmdb"` - Build with specific features

### Testing
- `make test` - Run the full test suite in release mode (excludes EF tests, beacon_chain, slasher, network, http_api)
- `make nextest-release` - Run tests using nextest (faster parallel test runner)
- `make test-beacon-chain` - Run beacon chain tests for all supported forks
- `make test-slasher` - Run slasher tests with all database backend combinations
- `make test-ef` - Download and run Ethereum Foundation test vectors
- `make test-full` - Complete test suite including linting, EF tests, and execution engine tests
- `cargo test -p <package_name>` - Run tests for a specific package
- `FORK_NAME=electra cargo nextest run -p beacon_chain` - Run tests for specific fork

### Linting and Code Quality  
- `make lint` - Run Clippy linter with project-specific rules
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

### Error Handling
- Avoid functions that could panic at runtime (e.g., `expect` or `unwrap`)
- Use proper error handling with `Result` types and graceful error propagation

### Rayon Usage
- Avoid using the rayon global thread pool as it results in CPU oversubscription when the beacon processor has fully allocated all CPUs to workers
- Use scoped rayon pools started by beacon processor for computational intensive tasks

### Locks
- Take great care to avoid deadlocks when working with fork choice locks - seek detailed review ([reference](https://github.com/sigp/lighthouse/blob/40c2fd5ff4215bcc5c2eed00dcb40dedd6bcc88b/beacon_node/beacon_chain/src/canonical_head.rs#L9-L32))
- Keep lock scopes as narrow as possible to avoid blocking fast-responding functions like the networking stack
- Consider using `try_lock()` patterns where appropriate to avoid blocking

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
- Maintain schema continuity on `unstable` branch ([reference](https://github.com/sigp/lighthouse/pull/7661#discussion_r2176181303))
- Database migrations must be backward compatible

### Consensus Crate
- Use safe math methods like `saturating_xxx` or `checked_xxx`
- Critical that this crate behaves deterministically and MUST not have undefined behavior