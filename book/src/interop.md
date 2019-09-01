# Lighthouse Interop Guide

This guide is intended for other Ethereum 2.0 client developers performing
inter-operability testing with Lighthouse.

To allow for faster iteration cycles without the "merging to master" overhead,
we will use the [`interop`](https://github.com/sigp/lighthouse/tree/interop)
branch of [sigp/lighthouse](https://github.com/sigp/lighthouse/tree/interop)
for September 2019 interop.  **Please use ensure you `git checkout interop`
after cloning the repo.**

## Environment

All that is required for inter-op is a built and tested [development
environment](setup). When lighthouse boots, it will create the following
directories:

- `~/.lighthouse`: database and configuration for the beacon node.
- `~/.lighthouse-validator`: database and configuration for the validator
	client.

After building the binaries with `cargo build --release --all`, there will be a
`target/release` directory in the root of the Lighthouse repository. This is
where the `beacon_node` and `validator_client` binaries are located.

## Interop Procedure

The following scenarios are documented:

- [Starting a "quick-start" beacon node](#quick-start-beacon-node) from a
    `(validator_count, genesis)` tuple.
- [Starting a validator client](#validator-client) with `n` interop keypairs.
- [Starting a node from a genesis state file](#starting-from-a-genesis-file).
- [Exporting a genesis state file](#exporting-a-genesis-file) from a running Lighthouse
	node.

First, setup a Lighthouse development environment and navigate to the
`target/release` directory (this is where the binaries are located).

#### Quick-start Beacon Node


To start the node (each time creating a fresh database and configuration in
`~/.lighthouse`), use:

```
$ ./beacon_node testnet -f quick 8 1567222226
```

>This method conforms the ["Quick-start
genesis"](https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#quick-start-genesis)
method in the `ethereum/eth2.0-pm` repository.
>
> The `-f` flag ignores any existing database or configuration, backing them up
before re-initializing. `8` is the validator count and `1567222226` is the
genesis time.
>
> See `$ ./beacon_node testnet quick --help` for more configuration options.

#### Validator Client

**TODO**

#### Starting from a genesis file

**TODO**

#### Exporting a genesis file

**TODO**
