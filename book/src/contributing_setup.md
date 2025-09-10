# Development Environment

Most Lighthouse developers work on Linux or MacOS, however Windows should still
be suitable.

First, follow the [`Installation Guide`](./installation.md) to install
Lighthouse. This will install Lighthouse to your `PATH`, which is not
particularly useful for development but still a good way to ensure you have the
base dependencies.

The additional requirements for developers are:

- [`anvil`](https://github.com/foundry-rs/foundry/tree/master/crates/anvil). This is used to
  simulate the execution chain during tests. You'll get failures during tests if you
  don't have `anvil` available on your `PATH`.
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

### test_logger

The test_logger, located in `/common/logging/` can be used to create a `Logger` that by
default returns a NullLogger. But if `--features 'logging/test_logger'` is passed while
testing the logs are displayed. This can be very helpful while debugging tests.

Example:

```
$ cargo nextest run -p beacon_chain -E 'test(validator_pubkey_cache::test::basic_operation)' --features 'logging/test_logger'
    Finished test [unoptimized + debuginfo] target(s) in 0.20s
     Running unittests (target/debug/deps/beacon_chain-975363824f1143bc)

running 1 test
Sep 19 19:23:25.192 INFO Beacon chain initialized, head_slot: 0, head_block: 0x2353…dcf4, head_state: 0xef4b…4615, module: beacon_chain::builder:649
Sep 19 19:23:25.192 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
Sep 19 19:23:26.798 INFO Beacon chain initialized, head_slot: 0, head_block: 0x2353…dcf4, head_state: 0xef4b…4615, module: beacon_chain::builder:649
Sep 19 19:23:26.798 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
Sep 19 19:23:28.407 INFO Beacon chain initialized, head_slot: 0, head_block: 0xdcdd…501f, head_state: 0x3055…032c, module: beacon_chain::builder:649
Sep 19 19:23:28.408 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
Sep 19 19:23:30.069 INFO Beacon chain initialized, head_slot: 0, head_block: 0xa739…1b22, head_state: 0xac1c…eab6, module: beacon_chain::builder:649
Sep 19 19:23:30.069 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
test validator_pubkey_cache::test::basic_operation ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 51 filtered out; finished in 6.46s
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
