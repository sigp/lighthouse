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

## Explicit PQ reference artifacts

The `pq_state_transition`, `pq_network`, and `pq_ssz` targets run an explicitly selected
minimal/PQ artifact without replacing the installed release fixtures. Their tests are
ignored by default because the usual reference-test release does not contain these
fixtures. `CONSENSUS_SPEC_TESTS_DIR` must contain `tests/minimal/pq`.

```sh
export CONSENSUS_SPEC_TESTS_DIR=/path/to/extracted-artifact
export PQ_REFERENCE_RESULTS_DIR=/path/to/results/real
export RUST_MIN_STACK=8388608
export RAYON_NUM_THREADS=4
cargo test --locked --release --no-fail-fast -p ef_tests --features ef_tests,spec-minimal \
  --test pq_state_transition --test pq_network -- --ignored --test-threads=1

export PQ_REFERENCE_RESULTS_DIR=/path/to/results/fake
cargo test --locked --release --no-fail-fast -p ef_tests --features ef_tests,spec-minimal,fake_crypto \
  --test pq_state_transition --test pq_network --test pq_ssz -- --ignored --test-threads=1

python3 testing/ef_tests/scripts/summarize_pq_reference.py \
  --fixtures "$CONSENSUS_SPEC_TESTS_DIR" \
  --reports /path/to/results/real /path/to/results/fake \
  --output /path/to/results/summary.json
```

Network tests start a local mock execution endpoint and need permission to listen on
localhost. The SSZ target uses `fake_crypto` because random byte fixtures include BLS
values that are deliberately not valid curve points. This does **not** disable XMSS
verification: fixtures generated with XMSS disabled require additional harness support.

Every handler writes individual case outcomes to JSON, including load errors, failures,
crypto-mode skips, known skips, and unsupported types. The summary checks the artifact's
manifest inventory so missing coverage cannot silently disappear. A Rust test group
finishing successfully is not the same as every fixture passing: consult the case counts.
