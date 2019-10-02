# Simple Local Testnet

With a functional [development environment](./setup.md), starting a local multi-node
testnet is easy:

1. Start the first node: `$ ./beacon_node testnet -f recent 8`
1. Start a validator client: `$ ./validator_client testnet -b insecure 0 8`
1. Start more nodes with `$ ./beacon_node -b 10 testnet -f bootstrap
   http://localhost:5052`
   - Increment the `-b` value by `10` for each additional node.

## Detailed Instructions

First, setup a Lighthouse development environment and navigate to the
`target/release` directory (this is where the binaries are located).

## Starting a beacon node

Start a new node (creating a fresh database and configuration in `~/.lighthouse`), using:

```bash
$ ./beacon_node testnet -f recent 8
```

> Notes:
>
> - The `-f` flag ignores any existing database or configuration, backing them
>   up before re-initializing.
> - `8` is number of validators with deposits in the genesis state.
> - See `$ ./beacon_node testnet recent --help` for more configuration options,
>   including `minimal`/`mainnet` specification.

## Starting a validator client

In a new terminal window, start the validator client with:

```bash
$ ./validator_client testnet -b insecure 0 8
```

> Notes:
>
> - The `-b` flag means the validator client will "bootstrap" specs and config
>   from the beacon node.
> - The `insecure` command uses predictable, well-known private keys. Since
>   this is just a local testnet, these are fine.
> - The `0 8` indicates that this validator client should manage 8 validators,
>   starting at validator 0 (the first deposited validator).
> - The validator client will try to connect to the beacon node at `localhost`.
>   See `--help` to configure that address and other features.

## Adding another beacon node

You may connect another (non-validating) node to your local network using the
lighthouse `bootstrap` command.

In a new terminal window, run:


```bash
$ ./beacon_node -b 10 testnet -r bootstrap
```

> Notes:
>
> - The `-b` (or `--port-bump`) increases all the listening TCP/UDP ports of
>   the new node to `10` higher. Your first node's HTTP server was at TCP
>   `5052` but this one will be at `5062`.
> - The `-r` flag creates a new data directory with a random string appended
>   (avoids data directory collisions between nodes).
> - The default bootstrap HTTP address is `http://localhost:5052`. The new node
>   will download configuration via HTTP before starting sync via libp2p.
> - See `$ ./beacon_node testnet bootstrap --help` for more configuration.
