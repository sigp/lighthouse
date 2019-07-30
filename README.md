# Lighthouse: Ethereum 2.0

An open-source Ethereum 2.0 client, written in Rust and maintained by Sigma Prime.

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Gitter Badge]][Gitter Link]

[Build Status]: https://gitlab.sigmaprime.io/sigp/lighthouse/badges/master/build.svg
[Build Link]: https://gitlab.sigmaprime.io/sigp/lighthouse/pipelines
[Gitter Badge]: https://badges.gitter.im/Join%20Chat.svg
[Gitter Link]: https://gitter.im/sigp/lighthouse
[Doc Status]: https://img.shields.io/badge/docs-master-blue.svg
[Doc Link]: http://lighthouse-docs.sigmaprime.io/

## Overview

Lighthouse is:

- Fully open-source, licensed under Apache 2.0.
- Security-focused, fuzzing has begun and security reviews are planned
	for late-2019.
- Built in [Rust](https://www.rust-lang.org/), a modern language providing unique safety guarantees and
	excellent performance (comparable to C++).
- Funded by various organisations, including Sigma Prime, the
	Ethereum Foundation, ConsenSys and private individuals.
- Actively working to promote an inter-operable, multi-client Ethereum 2.0.


## Development Status

Lighthouse, like all Ethereum 2.0 clients, is a work-in-progress. Instructions
are provided for running the client, however these instructions are designed
for developers and researchers working on the project. We do not (yet) provide
user-facing functionality.

Current development overview:

- Specification `v0.8.1` implemented, optimized and passing test vectors.
- Rust-native libp2p with Gossipsub and Discv5.
- Metrics via Prometheus.
- Basic gRPC API, soon to be replaced with RESTful HTTP/JSON.

### Roadmap

- **Early-September 2019**: `lighthouse-0.0.1` release: A stable testnet for
  developers with a useful HTTP API.
- **September 2019**: Inter-operability with other Ethereum 2.0 clients.
- **October 2019**: Public, multi-client testnet with user-facing functionality.
- **January 2020**: Production Beacon Chain testnet.

## Usage

Lighthouse consists of multiple binaries:

- [`beacon_node/`](beacon_node/): produces and verifies blocks from the P2P
	connected validators and the P2P network. Provides an API for external services to
	interact with Ethereum 2.0.
- [`validator_client/`](validator_client/): connects to a `beacon_node` and
	performs the role of a proof-of-stake validator.
- [`account_manager/`](account_manager/): a stand-alone component providing key
	management and creation for validators.

### Simple Local Testnet

**Note: these instructions are intended for developers and researchers. We do
not yet support end-users.**

In this example we use the `account_manager` to create some keys, launch two
`beacon_node` instances and connect a `validator_client` to one. The two
`beacon_nodes` should stay in sync and build a Beacon Chain.

First, clone this repository, [setup a development
environment](docs/installation.md) and navigate to the root directory of this repository.

Then, run `$ cargo build --all --release` and navigate to the `target/release`
directory and follow the steps:

#### 1. Generate Validator Keys

Generate 16 validator keys and store them in `~/.lighthouse-validator`:

```
$ ./account_manager -d ~/.lighthouse-validator generate_deterministic -i 0 -n 16
```

_Note: these keys are for development only. The secret keys are
deterministically generated from low integers. Assume they are public
knowledge._

#### 2. Start a Beacon Node

This node will act as the boot node and provide an API for the
`validator_client`.

```
$ ./beacon_node --recent-genesis --rpc
```

_Note: `--recent-genesis` defines the genesis time as either the start of the
current hour, or half-way through the current hour (whichever is most recent).
This makes it very easy to create a testnet, but does not allow nodes to
connect if they were started in separate 30-minute windows._

#### 3. Start Another Beacon Node

In another terminal window, start another boot that will connect to the
running node.

The running node will display it's ENR as a base64 string. This ENR, by default, has a target address of `127.0.0.1` meaning that any new node will connect to this node via `127.0.0.1`. If a boot node should be connected to on a different address, it should be run with the `--discovery-address` CLI flag to specify how other nodes may connect to it.
```
$ ./beacon_node -r --boot-nodes <boot-node-ENR> --listen-address 127.0.0.1 --port 9001 --datadir /tmp/.lighthouse
```
Here <boot-node-ENR> is the ENR string displayed in the terminal from the first node. The ENR can also be obtained from it's default directory `.lighthouse/network/enr.dat`.

The `--datadir` flag tells this Beacon Node to store it's files in a different
directory. If you're on a system that doesn't have a `/tmp` dir (e.g., Mac,
Windows), substitute this with any directory that has write access.

Note that all future created nodes can use the same boot-node ENR. Once connected to the boot node, all nodes should discover and connect with each other.
#### 4. Start a Validator Client

In a third terminal window, start a validator client:

```
$ ./validator-client
```

You should be able to observe the validator signing blocks, the boot node
processing these blocks and publishing them to the other node. If you have
issues, try restarting the beacon nodes to ensure they have the same genesis
time. Alternatively, raise an issue and include your terminal output.

## Further Reading

- [About Lighthouse](docs/lighthouse.md): Goals, Ideology and Ethos surrounding
this implementation.
- [What is Ethereum Serenity](docs/serenity.md): an introduction to Ethereum Serenity.
- [Lighthouse Technical Documentation](http://lighthouse-docs.sigmaprime.io/): The Rust generated documentation, updated regularly.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or the
[company website](https://sigmaprime.io).

## Directory Structure

- [`beacon_node/`](beacon_node/): the "Beacon Node" binary and crates exclusively
	associated with it.
- [`docs/`](docs/): documentation related to the repository. This includes contributor
	guides, etc. (It does not include code documentation, which can be produced with `cargo doc`).
- [`eth2/`](eth2/): Crates containing common logic across the Lighthouse project. For
	example: Ethereum 2.0 types ([`BeaconBlock`](eth2/types/src/beacon_block.rs), [`BeaconState`](eth2/types/src/beacon_state.rs), etc) and
	SimpleSerialize (SSZ).
- [`protos/`](protos/): protobuf/gRPC definitions that are common across the Lighthouse project.
- [`validator_client/`](validator_client/): the "Validator Client" binary and crates exclusively
	associated with it.
- [`tests/`](tests/): code specific to testing, most notably contains the
	Ethereum Foundation test vectors.

## Contributing

**Lighthouse welcomes contributors.**

If you are looking to contribute, please head to our
[onboarding documentation](https://github.com/sigp/lighthouse/blob/master/docs/onboarding.md).

If you'd like to contribute, try having a look through the [open
issues](https://github.com/sigp/lighthouse/issues) (tip: look for the [good
first
issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
tag) and ping us on the [gitter](https://gitter.im/sigp/lighthouse) channel. We need
your support!

## Contact

The best place for discussion is the [sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).

## Donations

If you support the cause, we accept donations to help fund development:

`0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b` (donation.sigmaprime.eth)
