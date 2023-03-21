Hydra Fuzzer
============

The Hydra fuzzer is a fuzzer that targets fork choice, block production and other consensus-adjacent
components that are external to the state transition function. It simulates an attacker that controls
a portion of validators and broadcasts blocks with random delays to a set of simulated honest
nodes. More detail on the algorithm can be found in the [Design](#design) section below.

Hydra is implemented on top of the popular [AFL++][] fuzzer.

## Dependencies

You need a nightly Rust compiler:

```
rustup toolchain install nightly
```

Once you have a nightly compiler, install AFL:

```
cargo +nightly install afl
```

To run multiple parallel tasks you'll also need GNU screen. On Ubuntu:

```
sudo apt install screen
```

Hydra has only been tested on Linux and probably won't work on macOS/Windows.

## Running

The interface to the Hydra fuzzer is a Python script `hydra.py` with two main subcommands:

- `run`: start a new fuzzing session
- `repro`: replay a crash or test case

Both commands take a `--spec {minimal,mainnet}` flag to choose between 8 or 32 slots per epoch.

To start a fuzzing session using 16 parallel processes for the mainnet spec, first create a
starting corpus:

```
cd lighthouse/beacon_node/beacon_chain/fuzz # this directory

mkdir -p data/in

echo "lets start fuzzing" > data/in/start
```

Next, we need to tweak some kernel parameters so that AFL is happy:

```
sudo ./setup.sh
```

Then you can start Hydra like so:

```
./hydra.py run --spec mainnet --num-workers 16
```

This will create a new `screen` session with 16 windows running the AFL processes. You
can attach to it with `screen -x hydra`. Crashes found will be output to
`data/out/{worker}/crashes`.

You can check for crashes from all workers using a command like:

```
ls data/out/*/crashes/* | grep -v README
```

## Environment Variables

Hydra is configured via environment variables. Some useful ones are:

- `HYDRA_CONFIG_BASE`: choose the base configuration including the attacker's fraction of the
  network.
- `HYDRA_MAX_REORG_LENGTH`: choose the maximum length of re-org to be tolerated during testing.
  The default is 8 slots, but should be set lower if you're using the minimal spec.
- `HYDRA_DEBUG_LOGS`: enable/disable the output of Hydra-specific debug logs _on stdout_.
- `HYDRA_LOG_PERSPECTIVE`: enable/disable the output of Lighthouse debug logs _on stderr_, from the
   perspective of a single honest node.

For more information see `src/env.rs` and `src/config.rs`.

## Reproducing a crash

Usually when reproducing a crash you'll want both Hydra and Lighthouse logs:

```
env HYDRA_DEBUG_LOGS=true HYDRA_LOG_PERSPECTIVE=0 ./hydra.py repro --spec minimal data/out/worker0/crashes/example > stdout.log 2> stderr.log
```

## Design

_This is a description of how Hydra works at a high-level. It may become out of date as the
underlying code changes._

Hydra maintains the following state during simulation:

- `honest_nodes`: a list of beacon chain harnesses for honest nodes. Each node has its own in-memory
  database, fork choice and signing keys.
- `attacker`: a beacon chain harness used by the attacker.
- `hydra`: a collection of "viable" head states that the attacker may build a block upon. This is
  the key data-structure which gives the fuzzer its name.
- `u`: an instance of [`arbitrary::Unstructured`][unstructured] which the simulator uses to convert
   the random bytes from the fuzzer into attacker actions.
- `time`: a representation of the current time with sub-slot accuracy. Time is split into ticks
   with a configurable number of ticks per slot (default 3).

Hydra runs a loop with these key steps:

- At the start of a slot, all honest nodes propose blocks according to their view of the head.
  Honest blocks are broadcast with 0 delay and arrive immediately at all other honest nodes.
- At the attestation deadline tick, honest nodes sign and broadcast attestations according to
  their view of the head. Honest attestations are broadcast with 0 delay and arrive immediately
  at all other honest nodes.
- At the start of a slot, the attacker updates the Hydra head tracker and then randomly chooses
  heads to propose on. They choose based on the input bytes (via `Unstructured`) from the heads that
  they are eligible to propose on (selected as proposer). Each attacker proposer index proposes at
  most 1 block per slot (they don't commit any slashable offences). For each `(block, node)` the
  attacker chooses a random delay for the `block` to arrive at `node`. The spread of delays is
  limited by the `max_delay_difference` parameter which represents the honest nodes' ability to
  propagate blocks regardless of the attacker's attempt to withhold them.

The loop logic is contained in `src/runner.rs`.

The fuzzer is trying to trigger certain bad behaviours on the honest nodes. Currently this
includes:

- Logs at `ERROR` or `CRIT` level.
- Re-orgs longer than the `max_reorg_length` (`HYDRA_MAX_REORG_LENGTH`).

It achieves this via a custom logger implementation that snoops on the logs from the honest nodes
(see `src/log_interceptor.rs`).

The simulation terminates once the attacker runs out of entropy, at which point a few more
iterations are run to finish delivery of in-flight messages. If the attacker runs out of entropy
in the middle of the simulation then an error is returned and the simulation ends early (without
panicking). The fuzzer will usually extend the input in this case to explore more of the search
space, and the effort spent exploring aborted runs is not wasted as the fuzzer is still checking for
errors and re-orgs as it goes.

### Message Delivery

Messages from honest nodes are delivered instantly.

Attacker messages are queued at each node to be dequeued at a given tick.

If a message is undeliverable because one of its dependent messages hasn't arrived yet (e.g. its
parent block) then it is added to a separate queue of messages to be delivered immediately upon that
message's arrival. This model slightly favours the honest nodes but was found to be more realistic
than a previous approach that just naively requeued messages until they could be processed (the
attacker exploited the naive requeueing to split the network for extended periods during which some
attacker blocks were withheld).

Most of the message queueing logic is in `src/node.rs`.

### The Hydra Data Structure

The `Hydra` structure is a map from block roots to `BeaconState`s. It contains states for all blocks
descended from finalization, including those that are ancestors of other blocks in the set. Each
state is kept advanced to the current epoch so that it can be used to determine proposer shufflings
and used for block proposals on-demand.

Non-viable blocks/states are pruned from the Hydra based on their finalization information.

The logic for the `Hydra` is contained in `src/hydra.rs`.

## Limitations

The current limitations which may be removed in future versions are:

- [ ] The attacker only proposes blocks, they do not attest or sign aggregates.
- [ ] The attacker only sends valid messages.
- [ ] Neither the attacker nor the honest nodes send aggregate attestations.
- [ ] Neither the attacker nor the honest nodes send sync messages.
- [ ] Signature verification is required (slow).
- [ ] There is no slashing protection for the honest nodes, so we won't explore cases where the
      honest nodes get stuck due to slashing conditions.
- [ ] There is no slasher, so the attacker currently cannot attempt anything slashable.

[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[unstructured]: https://docs.rs/arbitrary/latest/arbitrary/struct.Unstructured.html
