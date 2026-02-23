---
name: test
description: Run targeted tests based on changed files. Automatically maps modified crates to the correct test commands.
argument-hint: "[fork-name] [--all]"
---

# Run Targeted Tests

Run the right tests for what was changed. Don't waste time with the full suite unless asked.

## Steps

1. **Find changed files**: Run `git diff --name-only HEAD -- '*.rs'` to see which Rust files were modified.

2. **Gate on compilation**: Run `cargo check` first. If it fails, fix errors before running tests.

3. **Map files to test commands** using this table:

| Changed path prefix | Test command |
|---|---|
| `consensus/state_processing/` | `cargo nextest run -p state_processing` |
| `consensus/types/` | `cargo nextest run -p types` |
| `consensus/fork_choice/` | `cargo nextest run -p fork_choice` |
| `consensus/proto_array/` | `cargo nextest run -p proto_array` |
| `beacon_node/beacon_chain/` | `FORK_NAME=electra cargo nextest run -p beacon_chain` |
| `beacon_node/store/` | `cargo nextest run -p store` |
| `beacon_node/network/` | `make test-network` |
| `beacon_node/http_api/` | `make test-http-api` |
| `beacon_node/operation_pool/` | `make test-op-pool` |
| `beacon_node/execution_layer/` | `cargo nextest run -p execution_layer` |
| `beacon_node/beacon_processor/` | `cargo nextest run -p beacon_processor` |
| `slasher/` | `cargo nextest run -p slasher` |
| `validator_client/` | `cargo nextest run -p validator_client` |
| `crypto/bls/` | `cargo nextest run -p bls` |
| `crypto/kzg/` | `cargo nextest run -p kzg` |
| `common/eth2/` | `cargo nextest run -p eth2` |
| Other crate | `cargo nextest run -p <crate-name>` (read Cargo.toml to find the package name) |

4. **Fork-specific testing**: If `$ARGUMENTS` contains a fork name (phase0, altair, bellatrix, capella, deneb, electra, fulu, gloas), use that as the `FORK_NAME` environment variable for beacon_chain, http_api, op_pool, and network tests.

5. **Full suite**: If `$ARGUMENTS` contains `--all`, skip the mapping and run `make test-release` instead.

6. **Dependency-aware testing**: If `consensus/types/` was changed, also run tests for `state_processing` and `beacon_chain` since they depend on types.

7. **Report results**: Summarize which tests passed and which failed. For failures, include the failing test names and error output.

## Notes

- Prefer `cargo nextest run` over `cargo test` for parallel execution
- beacon_chain tests default to electra fork. For broader coverage, run with multiple forks
- Network tests run phase0, electra, fulu by default via `make test-network`
- Full test suite takes ~20 minutes. Targeted tests are usually under 5 minutes
- Use `--no-fail-fast` flag for network tests (they continue despite individual failures)
