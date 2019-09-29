# Testnets

The Lighthouse CLI has a `testnet` sub-command to allow creating or connecting
to Eth2 beacon chain testnets.

For detailed documentation, use the `--help` flag on the CLI:

```
$ ./beacon_node testnet --help
```

```
$ ./validator_client testnet --help
```

## Examples

- [Starting from a`validator_count, genesis_time` tuple](#quick-start)
- [Starting a node from a genesis state file](#state-file)
- [Starting a validator client](#val-client)
- [Exporting a genesis state file](#export) from a running Lighthouse
	node

All examples assume a working [development environment](./setup.md) and
commands are based in the `target/release` directory (this is the build dir for
`cargo`).


### Start beacon node given a validator count and genesis_time


To start a brand-new beacon node (with no history) use:

```
$ ./beacon_node testnet -f quick 8 <GENESIS_TIME>
```

Where `GENESIS_TIME` is in [unix time](https://duckduckgo.com/?q=unix+time&t=ffab&ia=answer).

> Notes:
>
> - This method conforms the ["Quick-start
genesis"](https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#quick-start-genesis)
method in the `ethereum/eth2.0-pm` repository.
> - The `-f` flag ignores any existing database or configuration, backing them
>   up before re-initializing.
> - `8` is the validator count and `1567222226` is the genesis time.
> - See `$ ./beacon_node testnet quick --help` for more configuration options.

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

### Exporting a genesis file

Genesis states can downloaded from a running Lighthouse node via the HTTP API. Three content-types are supported:

- `application/json`
- `application/yaml`
- `application/ssz`

Using `curl`, a genesis state can be downloaded to `/tmp/genesis.ssz`:

```
$ curl --header "Content-Type: application/ssz" "localhost:5052/beacon/state/genesis" -o /tmp/genesis.ssz
```

## Advanced

Below are some CLI commands useful when working with testnets.

### Specify a boot node by multiaddr

You can specify a static list of multiaddrs when booting Lighthouse using
the `--libp2p-addresses` command.

#### Example:

```
$ ./beacon_node --libp2p-addresses /ip4/192.168.0.1/tcp/9000
```

### Specify a boot node by ENR

You can specify a static list of Discv5 addresses when booting Lighthouse using
the `--boot-nodes` command.

#### Example:

```
$ ./beacon_node --boot-nodes -IW4QB2Hi8TPuEzQ41Cdf1r2AUU1FFVFDBJdJyOkWk2qXpZfFZQy2YnJIyoT_5fnbtrXUouoskmydZl4pIg90clIkYUDgmlwhH8AAAGDdGNwgiMog3VkcIIjKIlzZWNwMjU2azGhAjg0-DsTkQynhJCRnLLttBK1RS78lmUkLa-wgzAi-Ob5
```

### Avoid port clashes when starting nodes

Starting a second Lighthouse node on the same machine will fail due to TCP/UDP
port collisions. Use the `-b` (`--port-bump`) flag to increase all listening
ports by some `n`.

#### Example:

Increase all ports by `10` (using multiples of `10` is recommended).

```
$ ./beacon_node -b 10
```

### Start a testnet with a custom slot time

Lighthouse can run at quite low slot times when there are few validators (e.g.,
`500 ms` slot times should be fine for 8 validators).

#### Example

The `-t` (`--slot-time`) flag specifies the milliseconds per slot.

```
$ ./beacon_node testnet -t 500 recent 8
```

> Note: `bootstrap` loads the slot time via HTTP and therefore conflicts with
> this flag.
