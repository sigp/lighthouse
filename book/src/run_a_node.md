# Run a Node

This document provides detail for users who want to run a Lighthouse beacon node.
You should be finished with one [Installation](./installation.md) method of your choice to continue with the following steps:

1. Set up an [execution node](#step-1-set-up-an-execution-node);
1. Enable [checkpoint sync](#step-2-choose-a-checkpoint-sync-provider);
1. Run [Lighthouse](#step-3-run-lighthouse);
1. [Check logs](#step-4-check-logs); and
1. [Further readings](#step-5-further-readings).

Checkpoint sync is *optional*; however, we recommend it since it is substantially faster
than syncing from genesis while still providing the same functionality.

## Step 1: Set up an execution node

The Lighthouse beacon node *must* connect to an execution engine in order to validate the transactions
present in blocks. Two flags are used to configure this connection:

- `--execution-endpoint`: the *URL* of the execution engine API. Often this will be
  `http://localhost:8551`.
- `--execution-jwt`: the *path* to the file containing the JWT secret shared by Lighthouse and the
  execution engine. This is a mandatory form of authentication that ensures that Lighthouse
has authority to control the execution engine.

Each execution engine has its own flags for configuring the engine API and JWT.
Please consult the relevant page of your execution engine for the required flags:

- [Geth: Connecting to Consensus Clients](https://geth.ethereum.org/docs/getting-started/consensus-clients)
- [Nethermind: Running Nethermind & CL](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge)
- [Besu: Connect to Mainnet](https://besu.hyperledger.org/en/stable/public-networks/get-started/connect/mainnet/)
- [Erigon: Beacon Chain (Consensus Layer)](https://github.com/ledgerwatch/erigon#beacon-chain-consensus-layer)

The execution engine connection must be *exclusive*, i.e. you must have one execution node
per beacon node. The reason for this is that the beacon node _controls_ the execution node.

## Step 2: Choose a checkpoint sync provider

Lighthouse supports fast sync from a recent finalized checkpoint.
The checkpoint sync is done using a [public endpoint](#use-a-community-checkpoint-sync-endpoint)
provided by the Ethereum community.

In [step 3](#step-3-run-lighthouse), when running Lighthouse,
we will enable checkpoint sync by providing the URL to the `--checkpoint-sync-url` flag.

### Use a community checkpoint sync endpoint

The Ethereum community provides various [public endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/) for you to choose from for your initial checkpoint state. Select one for your network and use it as the URL.

For example, the URL for Sigma Prime's checkpoint sync server for mainnet is `https://mainnet.checkpoint.sigp.io`,
which we will use in [step 3](#step-3-run-lighthouse).

## Step 3: Run Lighthouse

To run Lighthouse, we use the three flags from the steps above:
- `--execution-endpoint`;
- `--execution-jwt`; and
- `--checkpoint-sync-url`.

Additionally, we run Lighthouse with the `--network` flag, which selects a network:

- `lighthouse` (no flag): Mainnet.
- `lighthouse --network mainnet`: Mainnet.
- `lighthouse --network goerli`: Goerli (testnet).

Using the correct `--network` flag is very important; using the wrong flag can
result in penalties, slashings or lost deposits. As a rule of thumb, *always*
provide a `--network` flag instead of relying on the default.

For the testnets we support [Goerli](https://goerli.net/) (`--network goerli`),
[Sepolia](https://sepolia.dev/) (`--network sepolia`), and [Gnosis chain](https://www.gnosis.io/) (`--network gnosis`).

Minor modifications depend on if you want to run your node while [staking](#staking) or [non-staking](#non-staking).
In the following, we will provide examples of what a Lighthouse setup could look like.

### Staking

```
lighthouse bn \
  --network mainnet \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --http
```

A Lighthouse beacon node can be configured to expose an HTTP server by supplying the `--http` flag.
The default listen address is `127.0.0.1:5052`.
The HTTP API is required for the beacon node to accept connections from the *validator client*, which manages keys.

### Non-staking

``` 
lighthouse bn \
  --network mainnet \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --disable-deposit-contract-sync
```

Since we are not staking, we can use the `--disable-deposit-contract-sync` flag.

---

Once Lighthouse runs, we can monitor the logs to see if it is syncing correctly.

## Step 4: Check logs
Several logs help you identify if Lighthouse is running correctly. 

### Logs - Checkpoint sync
Lighthouse will print a message to indicate that checkpoint sync is being used:

```
INFO Starting checkpoint sync                remote_url: http://remote-bn:8000/, service: beacon
```

After a short time (usually less than a minute), it will log the details of the checkpoint
loaded from the remote beacon node:

```
INFO Loaded checkpoint block and state       state_root: 0xe8252c68784a8d5cc7e5429b0e95747032dd1dcee0d1dc9bdaf6380bf90bc8a6, block_root: 0x5508a20147299b1a7fe9dbea1a8b3bf979f74c52e7242039bd77cbff62c0695a, slot: 2034720, service: beacon
```

Once the checkpoint is loaded Lighthouse will sync forwards to the head of the chain.

If a validator client is connected to the node then it will be able to start completing its duties
as soon as forwards sync completes.

> **Security Note**: You should cross-reference the `block_root` and `slot` of the loaded checkpoint
> against a trusted source like another [public endpoint](https://eth-clients.github.io/checkpoint-sync-endpoints/),
> a friend's node, or a block explorer.

#### Backfilling Blocks

Once forwards sync completes, Lighthouse will commence a "backfill sync" to download the blocks
from the checkpoint back to genesis.

The beacon node will log messages similar to the following each minute while it completes backfill
sync:

```
INFO Downloading historical blocks  est_time: 5 hrs 0 mins, speed: 111.96 slots/sec, distance: 2020451 slots (40 weeks 0 days), service: slot_notifier
```

Once backfill is complete, a `INFO Historical block download complete` log will be emitted.

Check out the [FAQ](./checkpoint-sync.md#faq) for more information on checkpoint sync.

### Logs - Syncing

You should see that Lighthouse remains in sync and marks blocks
as `verified` indicating that they have been processed successfully by the execution engine:

```
INFO Synced, slot: 3690668, block: 0x1244…cb92, epoch: 115333, finalized_epoch: 115331, finalized_root: 0x0764…2a3d, exec_hash: 0x929c…1ff6 (verified), peers: 78
```


## Step 5: Further readings

Several other resources are the next logical step to explore after running your beacon node: 

- Learn how to [become a validator](./mainnet-validator.md);
- Explore how to [manage your keys](./key-management.md);
- Research on [validator management](./validator-management.md);
- Dig into the [APIs](./api.md) that the beacon node and validator client provide;
- Study even more about [checkpoint sync](./checkpoint-sync.md); or
- Investigate what steps had to be taken in the past to execute a smooth [merge migration](./merge-migration.md).

Finally, if you a struggling with anything, join our [Discord](https://discord.gg/cyAszAh). We are happy to help!