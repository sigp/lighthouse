# Fast Confirmation Rule (FCR)

Lighthouse supports the [fast confirmation rule](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/fast-confirmation.md) since v8.3.0. To enable fast confirmation rule, use the flag `--enable-fast-confirmation` on the beacon node. It is disabled by default. With fast confirmation, most blocks can be confirmed within 1-2 slots (12-24 seconds) instead of two epochs (~13 minutes).

## SSE Event

If you have subscribed to the beacon node Server-Sent-Event stream for fast confirmation, you should see the following:

```text
event:fast_confirmation
data:{"block":"0x335216055caedd9c20f8e4c5a3f314e1fc11f1031a42ffd030f344a7dfb28988","slot":"4046741","current_slot":"4046743"}
```

where `block` is the block root of `slot`, `slot` is the most recent confirmed block, and `current_slot` is the wall-clock slot. It is normal to see the fast confirmation event being emitted a few times for the same block/slot.

## Logs

When blocks are produced normally, you should see the following debug log every 12 seconds:

```text
DEBUG FCR advanced                                  confirmed: 0xd97ec7d7bfdf842e3b41a136fa4d55cba0586abec9724af517ab9504e75c2d8e, prev: 0xe1ce20d19963d332ba6a084de278fc71e2b0cdaac8c2e43a50ab5a0b0f
```

where `confirmed` is the block root of the most recent confirmed slot and `prev` is the block root of the previously confirmed slot. If there is a skipped slot, the next block will take a longer time to confirm. The above log will not be observed if the beacon node is syncing or the execution engine is syncing or offline, indicating that no new block has been confirmed.

After a restart of Lighthouse, the following logs will usually be seen across a new epoch:

```text
DEBUG FCR fell back to finalized                    prev_confirmed: 0x6bdf8b63e1f530ca02a6b97428fc876e1a50c3f4cd52447a54fd3e8cea891acf, finalized: 0x197ecc03b8f297ef308fbe6ff8dc1407a0e46c94039dfc8c9397acd10799a32c, slot: 4045664, reason: "epoch_too_old"
DEBUG FCR restarted from observed justified         prev_confirmed: 0x197ecc03b8f297ef308fbe6ff8dc1407a0e46c94039dfc8c9397acd10799a32c, justified: 0x0938fa402f4af908bed00fb695a447c1150ea07dd9741a4100eeff2db16ab69c, justified_epoch: 126426

```

The above two logs are harmless and expected after a restart.

If the beacon node has been offline for some time (e.g. one hour), when it is back online, you may see the following error log:

```text
ERROR Error running FCR: NodeNotFound(0xb471d7f9b3e760aea6a364dad4987fd033db672ec8f1efdc46a79f2bdd5427be)  current_slot: Slot(4046686), slot: 4046686
```

The error should go away once the beacon node is back in sync.

## Metrics

A Grafana dashboard for FCR is available in the [lighthouse-metrics](https://github.com/sigp/lighthouse-metrics) repository.
