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

## CLI Overview

The Lighthouse CLI has two primary tasks:

- **Starting** a new testnet chain using `$ ./beacon_node testnet`.
- **Resuming** an existing chain with `$ ./beacon_node` (omit `testnet`).

There are several methods for starting a new chain:

- `quick`: using the `(validator_client, genesis_time)` tuple.
- `recent`: as above but `genesis_time` is set to the start of some recent time
	window.
- `bootstrap`: a Lighthouse-specific method where we connect to a running node
	and download it's specification and genesis state via the HTTP API.

See `$ ./beacon_node testnet --help` for more detail.

Once a chain has been started, it can be resumed by running `$ ./beacon_node`
(potentially supplying the `--datadir`, if a non-default directory was used).


## Scenarios

The following scenarios are documented here:

- [Starting a "quick-start" beacon node](#quick-start-beacon-node) from a
    `(validator_count, genesis)` tuple.
- [Starting a validator client](#validator-client) with `n` interop keypairs.
- [Starting a node from a genesis state file](#starting-from-a-genesis-file).
- [Exporting a genesis state file](#exporting-a-genesis-file) from a running Lighthouse
	node.

All scenarios assume a working development environment and commands are based
in the `target/release` directory (this is the build dir for `cargo`).


#### Quick-start Beacon Node


To start the node (each time creating a fresh database and configuration in
`~/.lighthouse`), use:

```
$ ./beacon_node testnet -f quick 8 1567222226
```
> Notes:
>
> - This method conforms the ["Quick-start
genesis"](https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#quick-start-genesis)
method in the `ethereum/eth2.0-pm` repository.
> - The `-f` flag ignores any existing database or configuration, backing them
>   up before re-initializing.
> - `8` is the validator count and `1567222226` is the genesis time.
> - See `$ ./beacon_node testnet quick --help` for more configuration options.

#### Validator Client

Start the validator client with:

```
$ ./validator_client testnet -b insecure 0 8
```
> Notes:
>
> - The `-b` flag means the validator client will "bootstrap" specs and config
>   from the beacon node.
> - The `insecure` command dictates that the [interop
>   keypairs](https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#pubkeyprivkey-generation)
>   will be used.
> - The `0 8` indicates that this validator client should manage 8 validators,
>   starting at validator 0 (the first deposited validator).
> - The validator client will try to connect to the beacon node at `localhost`.
>   See `--help` to configure that address and other features.
> - The validator client will operate very unsafely in `testnet` mode, happily
>   swapping between chains and creating double-votes.

#### Starting from a genesis file

**TODO**

#### Exporting a genesis file

**TODO**
