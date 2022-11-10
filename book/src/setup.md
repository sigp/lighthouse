# Development Environment

Most Lighthouse developers work on Linux or MacOS, however Windows should still
be suitable.

First, follow the [`Installation Guide`](./installation.md) to install
Lighthouse. This will install Lighthouse to your `PATH`, which is not
particularly useful for development but still a good way to ensure you have the
base dependencies.

The additional requirements for developers are:
- [`ganache v7`](https://github.com/trufflesuite/ganache). This is used to
  simulate the execution chain during tests. You'll get failures during tests if you
  don't have `ganache` available on your `PATH` or if ganache is older than v7.
- [`cmake`](https://cmake.org/cmake/help/latest/command/install.html). Used by
  some dependencies. See [`Installation Guide`](./installation.md) for more info.
- [`protoc`](https://github.com/protocolbuffers/protobuf/releases) required for
  the networking stack.
- [`java 11 runtime`](https://openjdk.java.net/projects/jdk/). 11 is the minimum,
  used by web3signer_tests.


## Using `make`
Commands to run the test suite are available via the `Makefile` in the
project root for the benefit of CI/CD. We list some of these commands below so
you can run them locally and avoid CI failures:

- `$ make cargo-fmt`: (fast) runs a Rust code linter.
- `$ make test`: (medium) runs unit tests across the whole project.
- `$ make test-ef`: (medium) runs the Ethereum Foundation test vectors.
- `$ make test-full`: (slow) runs the full test suite (including all previous
  commands). This is approximately everything
	that is required to pass CI.

_The lighthouse test suite is quite extensive, running the whole suite may take 30+ minutes._

## Testing

As with most other Rust projects, Lighthouse uses `cargo test` for unit and
integration tests. For example, to test the `ssz` crate run:

```bash
$ cd consensus/ssz
$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 7.69s
     Running unittests (target/debug/deps/ssz-61fc26760142b3c4)

running 27 tests
test decode::impls::tests::awkward_fixed_length_portion ... ok
test decode::impls::tests::invalid_h256 ... ok
<snip>
test encode::tests::test_encode_length ... ok
test encode::impls::tests::vec_of_vec_of_u8 ... ok
test encode::tests::test_encode_length_above_max_debug_panics - should panic ... ok

test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/tests.rs (target/debug/deps/tests-f8fb1f9ccb197bf4)

running 20 tests
test round_trip::bool ... ok
test round_trip::first_offset_skips_byte ... ok
test round_trip::fixed_len_excess_bytes ... ok
<snip>
test round_trip::vec_u16 ... ok
test round_trip::vec_of_vec_u16 ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests ssz

running 3 tests
test src/decode.rs - decode::SszDecoder (line 258) ... ok
test src/encode.rs - encode::SszEncoder (line 57) ... ok
test src/lib.rs - (line 10) ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s$ cargo test -p eth2_ssz
```

Alternatively, since `lighthouse` is a cargo workspace you can use `-p eth2_ssz` where
`eth2_ssz` is the package name as defined  `/consensus/ssz/Cargo.toml`
```bash
$ head -2 consensus/ssz/Cargo.toml
[package]
name = "eth2_ssz"
$ cargo test -p eth2_ssz
    Finished test [unoptimized + debuginfo] target(s) in 7.69s
     Running unittests (target/debug/deps/ssz-61fc26760142b3c4)

running 27 tests
test decode::impls::tests::awkward_fixed_length_portion ... ok
test decode::impls::tests::invalid_h256 ... ok
<snip>
test encode::tests::test_encode_length ... ok
test encode::impls::tests::vec_of_vec_of_u8 ... ok
test encode::tests::test_encode_length_above_max_debug_panics - should panic ... ok

test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/tests.rs (target/debug/deps/tests-f8fb1f9ccb197bf4)

running 20 tests
test round_trip::bool ... ok
test round_trip::first_offset_skips_byte ... ok
test round_trip::fixed_len_excess_bytes ... ok
<snip>
test round_trip::vec_u16 ... ok
test round_trip::vec_of_vec_u16 ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests ssz

running 3 tests
test src/decode.rs - decode::SszDecoder (line 258) ... ok
test src/encode.rs - encode::SszEncoder (line 57) ... ok
test src/lib.rs - (line 10) ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s$ cargo test -p eth2_ssz
```

#### test_logger

The test_logger, located in `/common/logging/` can be used to create a `Logger` that by
default returns a NullLogger. But if `--features 'logging/test_logger'` is passed while
testing the logs are displayed. This can be very helpful while debugging tests.

Example:
```
$ cargo test -p beacon_chain validator_pubkey_cache::test::basic_operation --features 'logging/test_logger'
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
