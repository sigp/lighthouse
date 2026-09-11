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

The `light_client_sync` integration test runs the official `light_client/sync` vectors
through the transport-independent `decentralized_checkpoint_sync` crate:

```
cargo test -p ef_tests --features ef_tests --test light_client_sync -- --nocapture
```

It loads each case's `config.yaml`, resolves bootstrap/update fork digests (including Fulu
blob-schedule changes), and executes `process_update`, `force_update`, and `upgrade_store`.
After every step it checks the finalized and optimistic slots, beacon roots, and, from
Capella onward, historical-fork execution roots. Force updates are also checked not to
advance Lighthouse's independently authenticated checkpoint.

The pinned v1.7.0-alpha.14 generator emits only the **minimal** preset for sync. Altair
through Fulu are supported. Gloas-targeting cases in older-fork directories are reported
as known skips; Gloas/Heze handlers remain disabled. Unknown contexts and processing or
comparison errors fail the test. The sync test is disabled under `fake_crypto` so it cannot
claim successful signature verification with dummy BLS.

Parser and comparison regression tests do not require downloaded vectors:

```
cargo test -p ef_tests --lib cases::light_client_sync::tests
```

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
