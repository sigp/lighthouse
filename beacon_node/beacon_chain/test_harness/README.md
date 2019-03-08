# Test Harness

Provides a testing environment for the `BeaconChain`, `Attester` and `BlockProposer` objects.

This environment bypasses networking and client run-times and connects the `Attester` and `Proposer`
directly to the `BeaconChain` via an `Arc`.

The `BeaconChainHarness` contains a single `BeaconChain` instance and many `ValidatorHarness`
instances. All of the `ValidatorHarness` instances work to advance the `BeaconChain` by
producing blocks and attestations.

The crate consists of a library and binary, examples for using both are
described below.

## YAML

Both the library and the binary are capable of parsing tests from a YAML file,
in fact this is the sole purpose of the binary.

You can find YAML test cases [here](specs/). An example is included below:

```yaml
title: Validator Registry Tests
summary: Tests deposit and slashing effects on validator registry.
test_suite: validator_registry
fork: tchaikovsky
version: 1.0
test_cases:
  - config:
      slots_per_epoch: 64
      deposits_for_chain_start: 1000
      num_slots: 64
      skip_slots: [2, 3]
      deposits:
          # At slot 1, create a new validator deposit of 32 ETH.
        - slot: 1
          amount: 32
          # Trigger more deposits...
        - slot: 3
          amount: 32
        - slot: 5
          amount: 32
      proposer_slashings:
          # At slot 2, trigger a proposer slashing for validator #42.
        - slot: 2
          validator_index: 42
          # Trigger another slashing...
        - slot: 8
          validator_index: 13
      attester_slashings:
          # At slot 2, trigger an attester slashing for validators #11 and #12.
        - slot: 2
          validator_indices: [11, 12]
          # Trigger another slashing...
        - slot: 5
          validator_indices: [14]
    results:
      num_skipped_slots: 2
      states:
        - slot: 63
          num_validators: 1003
          slashed_validators: [11, 12, 13, 14, 42]
          exited_validators: []

```

Thanks to [prsym](http://github.com/prysmaticlabs/prysm) for coming up with the
base YAML format.

### Notes

Wherever `slot` is used, it is actually the "slot height", or slots since
genesis. This allows the tests to disregard the `GENESIS_EPOCH`.

### Differences from Prysmatic's format

1. The detail for `deposits`, `proposer_slashings` and `attester_slashings` is
   ommitted from the test specification. It assumed they should be valid
   objects.
2. There is a `states` list in `results` that runs checks against any state
   specified by a `slot` number. This is in contrast to the variables in
   `results` that assume the last (highest) state should be inspected.

#### Reasoning

Respective reasonings for above changes:

1. This removes the concerns of the actual object structure from the tests.
   This allows for more variation in the deposits/slashings objects without
   needing to update the tests. Also, it makes it makes it easier to create
   tests.
2. This gives more fine-grained control over the tests. It allows for checking
   that certain events happened at certain times whilst making the tests only
   slightly more verbose.

_Notes: it may be useful to add an extra field to each slashing type to
indicate if it should be valid or not. It also may be useful to add an option
for double-vote/surround-vote attester slashings. The `amount` field was left
on `deposits` as it changes the behaviour of state significantly._

## Binary Usage Example

Follow these steps to run as a binary:

1. Navigate to the root of this crate (where this readme is located)
2. Run `$ cargo run --release -- --yaml examples/validator_registry.yaml`

_Note: the `--release` flag builds the binary without all the debugging
instrumentation. The test is much faster built using `--release`. As is
customary in cargo, the flags before `--` are passed to cargo and the flags
after are passed to the binary._

### CLI Options

```
Lighthouse Test Harness Runner 0.0.1
Sigma Prime <contact@sigmaprime.io>
Runs `test_harness` using a YAML test_case.

USAGE:
    test_harness --log-level <LOG_LEVEL> --yaml <FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --log-level <LOG_LEVEL>    Logging level. [default: debug]  [possible values: error, warn, info, debug, trace]
        --yaml <FILE>              YAML file test_case.
```


## Library Usage Example

```rust
use test_harness::BeaconChainHarness;
use types::ChainSpec;

let validator_count = 8;
let spec = ChainSpec::few_validators();

let mut harness = BeaconChainHarness::new(spec, validator_count);

harness.advance_chain_with_block();

let chain = harness.chain_dump().unwrap();

// One block should have been built on top of the genesis block.
assert_eq!(chain.len(), 2);
```
