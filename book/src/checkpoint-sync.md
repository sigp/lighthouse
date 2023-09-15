# Checkpoint Sync

Since version 2.0.0 Lighthouse supports syncing from a recent finalized checkpoint. This is
substantially faster than syncing from genesis, while still providing all the same features.

If you would like to quickly get started with checkpoint sync, read the sections below on:

1. [Automatic Checkpoint Sync](#automatic-checkpoint-sync)
2. [Backfilling Blocks](#backfilling-blocks)

The remaining sections are for more advanced use-cases (archival nodes).

## Automatic Checkpoint Sync

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
> against a trusted source like a friend's node, a block explorer or some [public endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/).

Once the checkpoint is loaded Lighthouse will sync forwards to the head of the chain.

If a validator client is connected to the node then it will be able to start completing its duties
as soon as forwards sync completes.

### Use a community checkpoint sync endpoint

The Ethereum community provides various [public endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/) for you to choose from for your initial checkpoint state. Select one for your network and use it as the url for the `--checkpoint-sync-url` flag.  e.g.
```
lighthouse bn --checkpoint-sync-url https://example.com/ ...
```

### Adjusting the timeout

If the beacon node fails to start due to a timeout from the checkpoint sync server, you can try
running it again with a longer timeout by adding the flag `--checkpoint-sync-url-timeout`.

```
lighthouse bn --checkpoint-sync-url-timeout 300 --checkpoint-sync-url https://example.com/ ...
```

The flag takes a value in seconds. For more information see `lighthouse bn --help`.

## Backfilling Blocks

Once forwards sync completes, Lighthouse will commence a "backfill sync" to download the blocks
from the checkpoint back to genesis.

The beacon node will log messages similar to the following each minute while it completes backfill
sync:

```
INFO Downloading historical blocks  est_time: 5 hrs 0 mins, speed: 111.96 slots/sec, distance: 2020451 slots (40 weeks 0 days), service: slot_notifier
```

Once backfill is complete, a `INFO Historical block download complete` log will be emitted.

> Note: Since [v4.1.0](https://github.com/sigp/lighthouse/releases/tag/v4.1.0), Lighthouse implements rate-limited backfilling to mitigate validator performance issues after a recent checkpoint sync. This means that the speed at which historical blocks are downloaded is limited, typically to less than 20 slots/sec. This will not affect validator performance. However, if you would still prefer to sync the chain as fast as possible, you can add the flag `--disable-backfill-rate-limiting` to the beacon node.

> Note: Since [v4.2.0](https://github.com/sigp/lighthouse/releases/tag/v4.2.0), Lighthouse limits the backfill sync to only sync backwards to the weak subjectivity point (approximately 5 months). This will help to save disk space. However, if you would like to sync back to the genesis, you can add the flag `--genesis-backfill` to the beacon node.

## FAQ

1. What if I have an existing database? How can I use checkpoint sync?

The existing beacon database needs to be deleted before Lighthouse will attempt checkpoint sync.
You can do this by providing the `--purge-db` flag, or by manually deleting `<DATADIR>/beacon`.

2. Why is checkpoint sync faster?

Checkpoint sync prioritises syncing to the head of the chain quickly so that the node can perform
its duties. Additionally, it only has to perform lightweight verification of historic blocks:
it checks the hash chain integrity & proposer signature rather than computing the full state
transition.

3. Is checkpoint sync less secure?

No, in fact it is more secure! Checkpoint sync guards against long-range attacks that
genesis sync does not. This is due to a property of Proof of Stake consensus known as [Weak
Subjectivity][weak-subj].

## Reconstructing States

> This section is only relevant if you are interested in running an archival node for analysis
> purposes.

After completing backfill sync the node's database will differ from a genesis-synced node in the
lack of historic states. _You do not need these states to run a staking node_, but they are required
for historical API calls (as used by block explorers and researchers).

You can opt-in to reconstructing all of the historic states by providing the
`--reconstruct-historic-states` flag to the beacon node at any point (before, during or after sync).

The database keeps track of three markers to determine the availability of historic blocks and
states:

* `oldest_block_slot`: All blocks with slots greater than or equal to this value are available in the
  database. Additionally, the genesis block is always available.
* `state_lower_limit`: All states with slots _less than or equal to_ this value are available in
  the database. The minimum value is 0, indicating that the genesis state is always available.
* `state_upper_limit`: All states with slots _greater than or equal to_ `min(split.slot,
  state_upper_limit)` are available in the database. In the case where the `state_upper_limit` is
  higher than the `split.slot`, this means states are not being written to the freezer database.

Reconstruction runs from the state lower limit to the upper limit, narrowing the window of
unavailable states as it goes. It will log messages like the following to show its progress:

```
INFO State reconstruction in progress        remaining: 747519, slot: 466944, service: freezer_db
```

Important information to be aware of:

* Reconstructed states will consume several gigabytes or hundreds of gigabytes of disk space,
  depending on the [database configuration used](./advanced_database.md).
* Reconstruction will only begin once backfill sync has completed and `oldest_block_slot` is
  equal to 0.
* While reconstruction is running the node will temporarily pause migrating new data to the
  freezer database. This will lead to the database increasing in size temporarily (by a few GB per
  day) until state reconstruction completes.
* It is safe to interrupt state reconstruction by gracefully terminating the node – it will pick up
  from where it left off when it restarts.
* You can start reconstruction from the HTTP API, and view its progress. See the
  [`/lighthouse/database`](./api-lighthouse.md) APIs.

For more information on historic state storage see the
[Database Configuration](./advanced_database.md) page.

## Manual Checkpoint Sync

> This section is only relevant if you want to manually provide the checkpoint state and
> block instead of fetching them from a URL.

To manually specify a checkpoint use the following two flags:

* `--checkpoint-state`: accepts an SSZ-encoded `BeaconState` blob
* `--checkpoint-block`: accepts an SSZ-encoded `SignedBeaconBlock` blob

_Both_ the state and block must be provided and the state **must** match the block. The
state may be from the same slot as the block (unadvanced), or advanced to an epoch boundary,
in which case it will be assumed to be finalized at that epoch.

[weak-subj]: https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity/
