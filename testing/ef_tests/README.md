# Consensus Specification Tests

This crate parses and executes the test vectors at [ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests).

Functionality is achieved only via the `$ cargo test --features ef_tests` command.

## Running the Tests

Because the test vectors are very large, we do not download or run them by default.
To download them, run (in this directory):

```
$ make
```

_Note: this may download hundreds of MB of compressed archives from the
[ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests/),
which may expand into several GB of files._

If successful, you should now have the extracted tests in `./consensus-spec-tests`.

Run them with:

```
$ cargo test --features ef_tests
```

The tests won't run without the `ef_tests` feature enabled (this is to ensure that a top-level
`cargo test --all` won't fail on missing files).

The following is sometimes necessary to avoid stack overflow issues when running on MacOS:
```
$ export RUST_MIN_STACK=8388608
```

When debugging failing tests, it's often useful to disable parallization and output suppression:
```
$ cargo test --features ef_tests,disable_rayon -- --nocapture
```

## Light-client consumer sync

Run the following commands from the repository root. Consumer unit tests and runner
parser/comparison regression tests do not require downloaded vectors:

```sh
cargo test -p decentralized_checkpoint_sync
cargo test -p ef_tests --lib cases::light_client_sync::tests
```

The `light_client_sync` integration test runs the official `light_client/sync` vectors
through the transport-independent `decentralized_checkpoint_sync` crate. If the vectors
are not already available at the version configured in [Makefile](Makefile), download
them with `make -C testing/ef_tests` (this replaces the existing vector directory).
Then run both crypto backends:

```
cargo nextest run --release -p ef_tests --features ef_tests light_client_sync
cargo nextest run --release -p ef_tests --features ef_tests,fake_crypto light_client_sync
```

It loads each case's `config.yaml`, resolves bootstrap/update fork digests (including Fulu
blob-schedule changes), and executes `process_update`, `force_update`, and `upgrade_store`.
After every step it checks the finalized and optimistic slots, beacon roots, and, from
Capella onward, historical-fork execution roots. Force updates are also checked not to
advance Lighthouse's independently authenticated checkpoint.

The sync integration test uses the **minimal** preset. Altair through Fulu are supported.
Gloas/Heze are explicitly disabled because Lighthouse does not implement their light-client
types. Nine named Gloas-targeting cases in older-fork
directories are also explicitly disabled before execution; these are logged as disabled,
not counted as passing or returned as known failures. Any other new case is enabled by
default. Unknown contexts and bootstrap, process, force, upgrade or comparison errors fail
the test; failures are never converted into skips.

Both commands run the same consumer code and the same vectors. The real-crypto run checks
BLS signatures; the existing `bls/fake_crypto` backend uses dummy BLS operations, so its run
checks parsing, Merkle proofs and state-machine behavior, not BLS security. Both commands
also select the runner's parser/comparison and fixture-backed regression tests, which
check error propagation and comparison failures after each step.

To run only the integration test and display per-fork results and disabled cases:

```sh
cargo test --release -p ef_tests --test light_client_sync --features ef_tests -- --nocapture
```

The integration test runs multiple official cases inside one Rust test. Individual EF
case names are not selectable with Cargo or nextest test-name filters.

For the complete EF suite, `make test-ef` downloads the configured vectors, runs both
crypto backends, and checks vector-file access. Use `make run-ef-tests` to reuse a complete
download of the configured version. The file-access check requires the full suite, not
just the light-client sync tests.

This tests the consumer state machine, not provider data collection, HTTP/P2P transport,
or checkpoint startup integration. The vectors' `finalized_header` means spec state;
it must not be confused with `VerifiedFinalizedHeader` after a forced update.

## Saving Space

When you download the tests, the downloaded archives will be kept in addition to the extracted
files. You have several options for saving space:

1. Delete the archives (`make clean-archives`), and keep the extracted files. Suitable for everyday
   use, just don't re-run `make` or it will redownload the archives.
2. Delete the extracted files (`make clean-test-files`), and keep the archives. Suitable for CI, or
   temporarily saving space. If you re-run `make` it will extract the archives rather than
   redownloading them.
3. Delete everything (`make clean`). Good for updating to a new version, or if you no longer wish to
   run the EF tests.
