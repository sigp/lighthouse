# Lighthouse Inter-Op Docs

_These documents are intended for a highly technical audience, specifically
Ethereum 2.0 implementers._

This document provides details on how to use Lighthouse for inter-op testing.

## Steps

_Note: binaries are compiled into the `target/release` directory of the
repository. In this example, we run binaries assuming the user is in this
directory. E.g., running the beacon node binary can be achieved with
`$ ./target/release/beacon_node`. Those familiar  with `cargo` may use the
equivalent (and more-convenient) `cargo run --release --` commands._

1. Setup a Lighthouse [development environment](env.md).
1. Build all the binaries using `cargo build --all --release`
1. Create default configuration files by running `$ ./beacon_node` and pressing
   Ctrl+C after the node has started.
1. Follow the steps in [Genesis](#genesis) to configure the genesis state.
1. Follow the steps in [Networking](#networking) to launch a node with
   appropriate networking parameters.

## Genesis

Lighthouse supports the following methods for generating a genesis state:

- [`Yaml`](#yaml): loads the genesis state from some YAML file (recommended
	method).
- [`Generated`](#generated): generates a state given a `(validator_count,
	genesis_time)`
	tuple. _Note: this method is not yet fully specified and the state
	generated is almost certainly not identical to other implementations._
- [`RecentGenesis`](#recentgenesis): identical to `Generated`, however the
	`genesis_time` is set
	to the previous 30-minute window. For example, if a state is generated at
	`0845`, the genesis time will be `0830`.

You may configure a `beacon_node` to use one of these methods using the
[`beacon_node.toml`](README.md#beacon-nodetoml). There is a [documented
example](config_examples/) configuration file which includes an example for
each of these methods (see the `genesis_state` object).

### Yaml

This method involves loading a `BeaconState` from a YAML file. We provide
instructions for generating that YAML file and starting from it. If starting
from a pre-existing YAML file, simply skip the generation steps.

#### Generating a YAML file

The [cli_util](/tests/cli_util) generate YAML genesis state files. You can run
`$ ./cli_util genesis_yaml -h` to see documentation. We provide an example to
generate a YAML file with the following properties:

- 10 initial validators, each with [deterministic
	keypairs](https://github.com/ethereum/eth2.0-pm/issues/60#issuecomment-512157915).
- The genesis file is stored in `~/.lighthouse/`, the default data directory
	(an absolute path must be supplied).
- Genesis time is set to the time when the command is run (it can be customized
	with the `-g` flag).

```
$ ./cli_util genesis_yaml -n 10 -f /home/user/.lighthouse/genesis_state.yaml
```

#### Configuring the Beacon Node

Modify the [`beacon-node.toml`](README.md#beacon-nodetoml) file to have the
following `genesiss_state` object (choosing the `file`):

```
[genesis_state]
type = "Yaml"
file = "/home/user/.lighthouse/genesis_state.yaml"
```

### Generated

Modify the [`beacon-node.toml`](README.md#beacon-nodetoml) file to have the
following `genesis_state` object (choosing the `validator_count` and
`genesis_time`):

```
[genesis_state]
type = "Generated"
validator_count = 16
genesis_time = 1564620118
```

### RecentGenesis

Modify the [`beacon-node.toml`](README.md#beacon-nodetoml) file to have the
following `genesis_state` object (choosing the `validator_count`):

```
[genesis_state]
type = "RecentGenesis"
validator_count = 16
```

## Networking

_TODO: provide details on config required to connect to some IP address._

## References

The BLS key generation method used should be identical to [this
implementation](https://github.com/ethereum/eth2.0-pm/issues/60#issuecomment-512157915).
