# Development Environment

Most Lighthouse developers work on Linux or MacOS, however Windows should still
be suitable.

First, follow the [`Installation Guide`](./installation.md) to install
Lighthouse. This will install Lighthouse to your `PATH`, which is not
particularly useful for development but still a good way to ensure you have the
base dependencies.

The additional requirements for developers are:

- [`cmake`](https://cmake.org/cmake/help/latest/command/install.html). Used by
  some dependencies. See [`Installation Guide`](./installation.md) for more info.
- [`java 17 runtime`](https://openjdk.java.net/projects/jdk/). 17 is the minimum,
  used by web3signer_tests.

## Using `make`

Commands to run the test suite are available via the `Makefile` in the
project root for the benefit of CI/CD. We list some of these commands below so
you can run them locally and avoid CI failures:

- `$ make cargo-fmt`: (fast) runs a Rust code formatting check.
- `$ make lint`: (fast) runs a Rust code linter.
- `$ make test`: (medium) runs unit tests across the whole project using nextest.
- `$ make test-ef`: (medium) runs the Ethereum Foundation test vectors.
- `$ make test-full`: (slow) runs the full test suite (including all previous
  commands). This is approximately everything
 that is required to pass CI.

_The lighthouse test suite is quite extensive, running the whole suite may take 30+ minutes._

## Testing

Lighthouse uses `cargo nextest` for unit and integration tests. Nextest provides better parallelization and is used by CI. For example, to test the `safe_arith` crate run:

```bash
$ cd consensus/safe_arith
$ cargo nextest run
    Finished test [unoptimized + debuginfo] target(s) in 0.43s
    ------------
     Nextest run ID: 01234567-89ab-cdef-0123-456789abcdef
     Starting 8 tests across 1 binary
        PASS [   0.001s] safe_arith tests::test_safe_add_u64
        PASS [   0.001s] safe_arith tests::test_safe_mul_u64
        <snip>
    ------------
     Summary [ 0.012s] 8 tests run: 8 passed, 0 skipped
```

Alternatively, since `lighthouse` is a cargo workspace you can use `-p safe_arith` where
`safe_arith` is the package name as defined in `/consensus/safe_arith/Cargo.toml`:

```bash
$ head -2 consensus/safe_arith/Cargo.toml
[package]
name = "safe_arith"
$ cargo nextest run -p safe_arith
    Finished test [unoptimized + debuginfo] target(s) in 0.43s
    ------------
     Nextest run ID: 01234567-89ab-cdef-0123-456789abcdef
     Starting 8 tests across 1 binary
        PASS [   0.001s] safe_arith tests::test_safe_add_u64
        PASS [   0.001s] safe_arith tests::test_safe_mul_u64
        <snip>
    ------------
     Summary [ 0.012s] 8 tests run: 8 passed, 0 skipped
```

### Integration tests

Due to the size and complexity of the test suite, Lighthouse uses a pattern that differs from how
[integration tests are usually defined](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html).
This pattern helps manage large test suites more effectively and ensures tests only run in release
mode to avoid stack overflow issues.

#### The "main pattern"

For packages with integration tests that require more than one file, Lighthouse uses the following
structure:

- A `main.rs` file is defined at `package/tests/main.rs` that declares other test files as modules
- In `package/Cargo.toml`, integration tests are explicitly configured:

    ```toml
    [package]
    autotests = false

    [[test]]
    name = "package_tests"
    path = "tests/main.rs"
    ```

#### Rust Analyzer configuration

This pattern, combined with `#![cfg(not(debug_assertions))]` directives in test files (which
prevent tests from running in debug mode), causes Rust Analyzer to not provide IDE services like
autocomplete and error checking in integration test files by default.

To enable IDE support for these test files, configure Rust Analyzer to disable debug assertions.
For VSCode users, this is already configured in the repository's `.vscode/settings.json` file:

```json
{
    "rust-analyzer.cargo.cfgs": [
        "!debug_assertions"
    ]
}
```

### Logging in tests

By default, when running tests, the logs will not be printed if the tests passed. For example, to run the tests for the `beacon_chain` package:

```bash
cargo test --release  -p beacon_chain
```

To always show the logs, run the tests with `-- --nocapture`.

```bash
cargo test --release  -p beacon_chain -- --nocapture
```

By default, the log shown is `DEBUG` level. This can be overridden using the environment variable `RUST_LOG`. For example, to only show logs with `INFO` level and above:

```bash
RUST_LOG=info cargo test --release  -p beacon_chain -- --nocapture
```

To only show logs from the `beacon_chain` crate and with `INFO` level and above:

```bash
RUST_LOG=beacon_chain=info cargo test --release  -p beacon_chain -- --nocapture
```

### Consensus Spec Tests

The
[ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests/)
repository contains a large set of tests that verify Lighthouse behaviour
against the Ethereum Foundation specifications.

These tests are quite large (100's of MB) so they're only downloaded if you run
`$ make test-ef` (or anything that runs it). You may want to avoid
downloading these tests if you're on a slow or metered Internet connection. CI
will require them to pass, though.

## Local Testnets

During development and testing it can be useful to start a small, local
testnet.

The
[scripts/local_testnet/](https://github.com/sigp/lighthouse/tree/unstable/scripts/local_testnet)
directory contains several scripts and a README that should make this process easy.
