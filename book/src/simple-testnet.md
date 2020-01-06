# Simple Local Testnet

First, [install Lighthouse](./installation.md).

Then, get the current unix time in seconds; you can use
[epochconverter.com](https://www.epochconverter.com/) or `$ date +%s`. It
should look like this `1576803034` and you should use it wherever we put
`<time>`.

> If you choose a time that's more than several minutes in the past the
> validator client will refuse to produce blocks. We will loosen this
> restriction in the future, the issue is tracked
> [here](https://github.com/sigp/lighthouse/issues/714).

## Starting a beacon node

Start a new node with:

```bash
$ lighthouse bn --http testnet -r quick 8 <time>
```

> Notes:
>
> - The `--http` flag starts the API so the validator can produce blocks.
> - The `-r` flag creates a random data directory to avoid clashes with other
>    nodes.
> - `8` is number of validators with deposits in the genesis state.
> - See `$ lighthouse bn testnet --help` for more configuration options,
>   including `minimal`/`mainnet` specification.

## Starting a validator client

In a new terminal window, start the validator client with:

```bash
$ lighthouse vc testnet insecure 0 8
```

> Notes:
>
> - The `insecure` command uses predictable, well-known private keys. Since
>   this is just a local testnet, these are fine.
> - The `0 8` indicates that this validator client should manage 8 validators,
>   starting at validator 0 (the first deposited validator).
> - The validator client will try to connect to the beacon node at `localhost`.
>   See `--help` to configure that address and other features.

## Adding another beacon node

You may connect another (non-validating) node to your local network by starting
a new terminal and running:


```bash
lighthouse bn -z --libp2p-addresses /ip4/127.0.0.1/tcp/9000 testnet -r quick 8 <time>
```

> Notes:
>
> - The `z` (or `--zero-ports`) flag sets all listening ports to be zero, which then
>   means that the OS chooses random available ports. This avoids port
>   collisions with the first node.
> - The `--libp2p-addresses` flag instructs the new node to connect to the
>   first node.
