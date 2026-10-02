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

After a restart of Lighthouse, the following logs will usually be seen:

```text
DEBUG FCR restored a root confirmed before the restart  root: 0xcdfb8947cf88870b6e4721f27f7470f07478644419d6347fa01f871b00b25ca2
```

At the first epoch boundary after the restart, the following logs are usually seen:

``` 
DEBUG FCR fell back to finalized                    prev_confirmed: 0x1f92a52bf914720564776a1a392a7e10ed7cd998141fbcbd708622ba8ff5cc0d, finalized: 0xb8dfdf0b53d01b5197c058bf6b23891a826a5d3f606da195b4b71d4ad78891e1, slot: 4052704, reason: "epoch_too_old"
DEBUG FCR restarted from observed justified         prev_confirmed: 0xb8dfdf0b53d01b5197c058bf6b23891a826a5d3f606da195b4b71d4ad78891e1, justified: 0xd5b68e49a23eced36dc5693374660aaf63d707a88efb0d52363c4d10795034a4, justified_epoch: 126646
```

The above logs are harmless and expected after a restart.

If the beacon node has been offline for some time (e.g. one hour), when it is back online, you may see the following error log:

```text
ERROR Error running FCR: NodeNotFound(0xb471d7f9b3e760aea6a364dad4987fd033db672ec8f1efdc46a79f2bdd5427be)  current_slot: Slot(4046686), slot: 4046686
```

The error should go away once the beacon node is back in sync.

## Metrics

A Grafana dashboard for FCR is available in the [lighthouse-metrics](https://github.com/sigp/lighthouse-metrics) repository.
