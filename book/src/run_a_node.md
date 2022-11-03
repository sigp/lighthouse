# Run a Node

This document provides detail for users who want to run a Lighthouse beacon node.
You should be finished with one [Installation](./installation.md) of your choice to continue with the following steps:

1. Perform [Checkpoint sync](#step-1-checkpoint-sync); and
2. [Connect to an execution engine](#step-2-connect-to-an-execution-engine).

Checkpoint sync is *optional*; however,  we recommend it since it is substantially faster
than syncing from genesis while still providing all the same features.

## Step 1: Checkpoint sync

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

## Step 2: Connect to an execution engine

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
see the [FAQ](#faq) for further information about why many:1 and 1:many configurations are not
supported.

### FAQ

#### What if I have an existing database? How can I use checkpoint sync?

The existing beacon database needs to be deleted before Lighthouse will attempt checkpoint sync.
You can do this by providing the `--purge-db` flag, or by manually deleting `<DATADIR>/beacon`.

#### Why is checkpoint sync faster?

Checkpoint sync prioritises syncing to the head of the chain quickly so that the node can perform
its duties. Additionally, it only has to perform lightweight verification of historic blocks:
it checks the hash chain integrity & proposer signature rather than computing the full state
transition.

#### Is checkpoint sync less secure?

No, in fact it is more secure! Checkpoint sync guards against long-range attacks that
genesis sync does not. This is due to a property of Proof of Stake consensus known as [Weak
Subjectivity](https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity/).

---

#### Can I use `http://localhost:8545` for the execution endpoint?

Most execution nodes use port `8545` for the Ethereum JSON-RPC API. Unless custom configuration is
used, an execution node _will not_ provide the necessary engine API on port `8545`. You should
not attempt to use `http://localhost:8545` as your engine URL and should instead use
`http://localhost:8551`.

#### Can I share an execution node between multiple beacon nodes (many:1)?

It is **not** possible to connect more than one beacon node to the same execution engine. There must be a 1:1 relationship between beacon nodes and execution nodes.

The beacon node controls the execution node via the engine API, telling it which block is the
current head of the chain. If multiple beacon nodes were to connect to a single execution node they
could set conflicting head blocks, leading to frequent re-orgs on the execution node.

We imagine that in future there will be HTTP proxies available which allow users to nominate a
single controlling beacon node, while allowing consistent updates from other beacon nodes.

#### What about multiple execution endpoints (1:many)?

It is **not** possible to connect one beacon node to more than one execution engine. There must be a 1:1 relationship between beacon nodes and execution nodes.

Since an execution engine can only have one controlling BN, the value of having multiple execution
engines connected to the same BN is very low. An execution engine cannot be shared between BNs to
reduce costs.

Whilst having multiple execution engines connected to a single BN might be useful for advanced
testing scenarios, Lighthouse (and other consensus clients) have decided to support *only one*
execution endpoint. Such scenarios could be resolved with a custom-made HTTP proxy.
