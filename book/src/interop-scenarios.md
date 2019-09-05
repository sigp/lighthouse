# Interop Scenarios

Here we demonstrate some expected interop scenarios.

All scenarios assume a working [development environment](./setup.md) and
commands are based in the `target/release` directory (this is the build dir for
`cargo`).

Additional functions can be found in the [interop
cheat-sheet](./interop-cheat-sheet.md).

### Table of contents

- [Starting from a`validator_count, genesis_time` tuple](#quick-start)
- [Starting a node from a genesis state file](#state-file)
- [Starting a validator client](#val-client)
- [Exporting a genesis state file](#export) from a running Lighthouse
	node


<a name="quick-start"></a>
### Start beacon node given a validator count and genesis_time


To start a brand-new beacon node (with no history) use:

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

<a name="state-file"></a>
### Start Beacon Node given a genesis state file

A genesis state can be read from file using the `testnet file` subcommand.
There are three supported formats:

- `ssz` (default)
- `json`
- `yaml`

Start a new node using `/tmp/genesis.ssz` as the genesis state:

```
$ ./beacon_node testnet --spec minimal -f file ssz /tmp/genesis.ssz
```

> Notes:
>
> - The `-f` flag ignores any existing database or configuration, backing them
>   up before re-initializing.
> - See `$ ./beacon_node testnet file --help` for more configuration options.
> - The `--spec` flag is required to allow SSZ parsing of fixed-length lists.

<a name="val-client"></a>
### Start an auto-configured validator client

To start a brand-new validator client (with no history) use:

```
$ ./validator_client testnet -b insecure 0 8
```

> Notes:
>
> - The `-b` flag means the validator client will "bootstrap" specs and config
>   from the beacon node.
> - The `insecure` command dictates that the [interop keypairs](https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#pubkeyprivkey-generation)
>   will be used.
> - The `0 8` indicates that this validator client should manage 8 validators,
>   starting at validator 0 (the first deposited validator).
> - The validator client will try to connect to the beacon node at `localhost`.
>   See `--help` to configure that address and other features.
> - The validator client will operate very unsafely in `testnet` mode, happily
>   swapping between chains and creating double-votes.

<a name="export"></a>
### Exporting a genesis file

Genesis states can downloaded from a running Lighthouse node via the HTTP API. Three content-types are supported:

- `application/json`
- `application/yaml`
- `application/ssz`

Using `curl`, a genesis state can be downloaded to `/tmp/genesis.ssz`:

```
$ curl --header "Content-Type: application/ssz" "localhost:5052/beacon/state/genesis" -o /tmp/genesis.ssz
```
