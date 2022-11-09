# Run a Node

This document provides detail for users who want to run a Lighthouse beacon node.
You should be finished with one [Installation](./installation.md) of your choice to continue with the following steps:

1. Perform [Checkpoint sync](#step-1-checkpoint-sync);
2. Set up an [execution node](#step-2-set-up-an-execution-node);
3. Run [Lighthouse](#step-3-run-lighthouse);
4. [Check logs](#step-4-check-logs); and
5. [Further reading](#step-5-further-reading).

Checkpoint sync is *optional*; however,  we recommend it since it is substantially faster
than syncing from genesis while still providing all the same features.

## Step 1: Choose a checkpoint sync provider

Since version 2.0.0 Lighthouse supports syncing from a recent finalized checkpoint.
The checkpoint sync can be done using [another synced beacon node](#automatic-checkpoint-sync) or a [public endpoint](#use-a-community-checkpoint-sync-endpoint) provided by the Ethereum community.

### Automatic checkpoint sync

To begin checkpoint sync you will need HTTP API access to another synced beacon node. Enable
checkpoint sync by providing the other beacon node's URL to `--checkpoint-sync-url`, alongside any
other flags:

```
lighthouse bn --checkpoint-sync-url "http://remote-bn:5052" ...
```

Lighthouse will print a message to indicate that checkpoint sync is being used:

```
INFO Starting checkpoint sync                remote_url: http://remote-bn:8000/, service: beacon
```

After a short time (usually less than a minute), it will log the details of the checkpoint
loaded from the remote beacon node:

```
INFO Loaded checkpoint block and state       state_root: 0xe8252c68784a8d5cc7e5429b0e95747032dd1dcee0d1dc9bdaf6380bf90bc8a6, block_root: 0x5508a20147299b1a7fe9dbea1a8b3bf979f74c52e7242039bd77cbff62c0695a, slot: 2034720, service: beacon
```

> **Security Note**: You should cross-reference the `block_root` and `slot` of the loaded checkpoint
> against a trusted source like a friend's node, or a block explorer.

Once the checkpoint is loaded Lighthouse will sync forwards to the head of the chain.

If a validator client is connected to the node then it will be able to start completing its duties
as soon as forwards sync completes.

### Use a community checkpoint sync endpoint

The Ethereum community provides various [public endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/) for you to choose from for your initial checkpoint state. Select one for your network and use it as the url for the `--checkpoint-sync-url` flag.  e.g.
```
lighthouse bn --checkpoint-sync-url https://example.com/ ...
```

### Backfilling Blocks

Once forwards sync completes, Lighthouse will commence a "backfill sync" to download the blocks
from the checkpoint back to genesis.

The beacon node will log messages similar to the following each minute while it completes backfill
sync:

```
INFO Downloading historical blocks  est_time: 5 hrs 0 mins, speed: 111.96 slots/sec, distance: 2020451 slots (40 weeks 0 days), service: slot_notifier
```

Once backfill is complete, a `INFO Historical block download complete` log will be emitted.

Checkout [FAQ](./checkpoint-sync.md#faq) for more information.

## Step 2: Set up an execution node

The Lighthouse beacon node *must* connect to an execution engine in order to validate the transactions
present in blocks. Two flags are used to configure this connection:

- `--execution-endpoint <URL>`: the URL of the execution engine API. Often this will be
  `http://localhost:8551`.
- `--execution-jwt <FILE>`: the path to the file containing the JWT secret shared by Lighthouse and the
  execution engine. This is a mandatory form of authentication that ensures that Lighthouse
has authority to control the execution engine.

```
lighthouse bn --execution-endpoint <URL> --execution-jwt <FILE>
```
Each execution engine has its own flags for configuring the engine API and JWT.
Please consult the relevant page of your execution engine for the required flags:

- [Geth: Connecting to Consensus Clients](https://geth.ethereum.org/docs/interface/consensus-clients)
- [Nethermind: Running Nethermind & CL](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge)
- [Besu: Connect to Mainnet](https://besu.hyperledger.org/en/stable/public-networks/get-started/connect/mainnet/)

The execution engine connection must be **exclusive**, i.e. you must have one execution node
per beacon node. The reason for this is that the beacon node _controls_ the execution node. Please
see the [FAQ](./merge-migration.md#faq) for further information about why many:1 and 1:many configurations are not
supported.

## Step 3: Run Lighthouse

Staking:

```
lighthouse bn \
  --http \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex 
```

Non-staking:

``` 
lighthouse bn \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --disable-deposit-contract-sync
```

## Step 4: Check logs

## Step 5: Further reading
[Become a Validator](./mainnet-validator.md)

[Validator Monitoring](./validator-monitoring.md)

[Checkpoint Sync](./checkpoint-sync.md)

[Merge Migration](./merge-migration.md)

[APIs](./api.md)
