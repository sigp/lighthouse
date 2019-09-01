# Simple Local Testnet

You can setup a local, two-node testnet in **Only Three CLI Commands™**.

Follow the [Quick instructions](#tldr) version if you're confident, or see
[Detailed instructions](#detail) for more.


## Quick instructions

Setup a development environment, build the project and navigate to the
`target/release` directory.

1. Start the first node: `$ ./beacon_node testnet -f recent 8`
1. Start a validator client: `$ ./validator_client testnet -b insecure 0 8`
1. Start another node `$ ./beacon_node -b 10 testnet -f bootstrap http://localhost:5052`

_Repeat #3 to add more nodes._

## Detailed instructions

First, setup a Lighthouse development environment and navigate to the
`target/release` directory (this is where the binaries are located).

## Starting the Beacon Node

Start a new node (creating a fresh database and configuration in `~/.lighthouse`), using:

```
$ ./beacon_node testnet -f recent 8
```

> Notes:
>
> - The `-f` flag ignores any existing database or configuration, backing them
>   up before re-initializing.
> - `8` is number of validators with deposits in the genesis state.
> - See `$ ./beacon_node testnet recent --help` for more configuration options,
>   including `minimal`/`mainnet` specification.

## Starting the Validator Client

In a new terminal window, start the validator client with:

```
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

## Adding another Beacon Node

You may connect another (non-validating) node to your local network using the
lighthouse `bootstrap` command.

In a new terminal terminal, run:


```
$ ./beacon_node -b 10 testnet -r bootstrap http://localhost:5052
```

> Notes:
>
> - The `-b` (or `--port-bump`) increases all the listening TCP/UDP ports of
>   the new node to `10` higher. Your first node's HTTP server was at TCP
>   `5052` but this one will be at `5062`.
> - The `-r` flag creates a new data directory in your home with a random
>   string appended, to avoid conflicting with any other running node.
> - The HTTP address is the API of the first node. The new node will download
>   configuration via HTTP before starting sync via libp2p.
