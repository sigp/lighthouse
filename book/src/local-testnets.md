# Local Testnets

> This section is about running your own private local testnets.
> - If you wish to join the ongoing public testnet, please read [become a validator](./become-a-validator.md).

It is possible to create local, short-lived Lighthouse testnets that _don't_
require a deposit contract and Eth1 connection. There are two components
required for this:

1. Creating a "testnet directory", containing the configuration of your new
   testnet.
1. Using the `--dummy-eth1` flag on your beacon node to avoid needing an Eth1
   node for block production.

There is a TL;DR (too long; didn't read), followed by detailed steps if the
TL;DR isn't adequate.

##  TL;DR

```bash
lcli new-testnet
lcli interop-genesis
lighthouse bn --testnet-dir ~/.lighthouse/testnet --dummy-eth1 --http
lighthouse vc --testnet-dir ~/.lighthouse/testnet --allow-unsynced testnet insecure 0 128
```

Optionally update the genesis time to now:

```bash
lcli change-genesis-time ~/.lighthouse/testnet/genesis.ssz $(date +%s)
```

## 1. Creating a testnet directory

### 1.1 Install `lcli`

This guide requires `lcli`, the "Lighthouse CLI tool". It is a development tool
used for starting testnets and debugging.

Install `lcli` from the root directory of this repository with:

```bash
cargo install --path lcli --force
```

### 1.2 Create a testnet directory

The default location for a testnet directory is `~/.lighthouse/testnet`. We'll
use this directory to keep the examples simple, however you can always specify
a different directory using the `--testnet-dir` flag.

Once you have `lcli` installed, create a new testnet directory with:

```bash
lcli new-testnet
```

> - This will create a "mainnet" spec testnet. To create a minimal spec use `lcli --spec minim new-testnet`.
> - The `lcli new-testnet` command has many options, use `lcli new-testnet --help` to see them.

### 1.3 Create a genesis state

Your new testnet directory at `~/.lighthouse/testnet` doesn't yet have a
genesis state (`genesis.ssz`). Since there's no deposit contract in this
testnet, there's no way for nodes to find genesis themselves.

Manually create an "interop" genesis state with `128` validators:

```bash
lcli interop-genesis 128
```

> - A custom genesis time can be provided with `-t`.
> - See `lcli interop-genesis --help` for more info.

## 2. Start the beacon nodes and validator clients

Now the testnet has been specified in `~/.lighthouse/testnet`, it's time to
start a beacon node and validator client.

### 2.1 Start a beacon node

Start a beacon node:

```bash
lighthouse bn --testnet-dir ~/.lighthouse/testnet --dummy-eth1 --http
```

> - `--testnet-dir` instructs the beacon node to use the spec we generated earlier.
> - `--dummy-eth1` uses deterministic "junk data" for linking to the eth1 chain, avoiding the requirement for an eth1 node. The downside is that new validators cannot be on-boarded after genesis.
> - `--http` starts the REST API so the validator client can produce blocks.

### 2.2 Start a validator client

Once the beacon node has started and begun trying to sync, start a validator
client:

```bash
lighthouse vc --testnet-dir ~/.lighthouse/testnet --allow-unsynced testnet insecure 0 128
```

> - `--testnet-dir` instructs the validator client to use the spec we generated earlier.
> - `--allow-unsynced` stops the validator client checking to see if the beacon node is synced prior to producing blocks.
> - `testnet insecure 0 128` instructs the validator client to use insecure
>    testnet private keys and that it should control validators from `0` to
>    `127` (inclusive).
