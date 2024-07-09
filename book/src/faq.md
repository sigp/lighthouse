# Frequently Asked Questions

## [Beacon Node](#beacon-node-1)

- [I see a warning about "Syncing deposit contract block cache" or an error about "updating deposit contract cache", what should I do?](#bn-deposit-contract)
- [I see beacon logs showing `WARN: Execution engine called failed`, what should I do?](#bn-ee)
- [I see beacon logs showing `Error during execution engine upcheck`, what should I do?](#bn-upcheck)
- [My beacon node is stuck at downloading historical block using checkpoint sync. What should I do?](#bn-download-historical)
- [I proposed a block but the beacon node shows `could not publish message` with error `duplicate` as below, should I be worried?](#bn-duplicate)
- [I see beacon node logs `Head is optimistic` and I am missing attestations. What should I do?](#bn-optimistic)
- [My beacon node logs `CRIT Beacon block processing error error: ValidatorPubkeyCacheLockTimeout`, what should I do?](#bn-timeout)
- [My beacon node logs `WARN BlockProcessingFailure outcome: MissingBeaconBlock`, what should I do?](#bn-missing-beacon)
- [After checkpoint sync, the progress of `downloading historical blocks` is slow. Why?](#bn-download-slow)
- [My beacon node logs `WARN Error processing HTTP API request`, what should I do?](#bn-http)
- [My beacon node logs `WARN Error signalling fork choice waiter`, what should I do?](#bn-fork-choice)
- [My beacon node logs `ERRO Aggregate attestation queue full`, what should I do?](#bn-queue-full)
- [My beacon node logs `WARN Failed to finalize deposit cache`, what should I do?](#bn-deposit-cache)
- [My beacon node logs `WARN Could not verify blob sidecar for gossip`, what does it mean?](#bn-blob)

## [Validator](#validator-1)

- [Why does it take so long for a validator to be activated?](#vc-activation)
- [Can I use redundancy in my staking setup?](#vc-redundancy)
- [I am missing attestations. Why?](#vc-missed-attestations)
- [Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?](#vc-head-vote)
- [Can I submit a voluntary exit message without a beacon node?](#vc-exit)
- [Does increasing the number of validators increase the CPU and other computer resources used?](#vc-resource)
- [I want to add new validators. Do I have to reimport the existing keys?](#vc-reimport)
- [Do I have to stop `lighthouse vc` the when importing new validator keys?](#vc-import)
- [How can I delete my validator once it is imported?](#vc-delete)

## [Network, Monitoring and Maintenance](#network-monitoring-and-maintenance-1)

- [I have a low peer count and it is not increasing](#net-peer)
- [How do I update lighthouse?](#net-update)
- [Do I need to set up any port mappings (port forwarding)?](#net-port-forwarding)
- [How can I monitor my validators?](#net-monitor)
- [My beacon node and validator client are on different servers. How can I point the validator client to the beacon node?](#net-bn-vc)
- [Should I do anything to the beacon node or validator client settings if I have a relocation of the node / change of IP address?](#net-ip)
- [How to change the TCP/UDP port 9000 that Lighthouse listens on?](#net-port)
- [Lighthouse `v4.3.0` introduces a change where a node will subscribe to only 2 subnets in total. I am worried that this will impact my validators return.](#net-subnet)
- [How to know how many of my peers are connected through QUIC?](#net-quic)

## [Miscellaneous](#miscellaneous-1)

- [What should I do if I lose my slashing protection database?](#misc-slashing)
- [I can't compile lighthouse](#misc-compile)
- [How do I check the version of Lighthouse that is running?](#misc-version)
- [Does Lighthouse have pruning function like the execution client to save disk space?](#misc-prune)
- [Can I use a HDD for the freezer database and only have the hot db on SSD?](#misc-freezer)
- [Can Lighthouse log in local timestamp instead of UTC?](#misc-timestamp)
- [My hard disk is full and my validator is down. What should I do?](#misc-full)

## Beacon Node

### <a name="bn-deposit-contract"></a> I see a warning about "Syncing deposit contract block cache" or an error about "updating deposit contract cache", what should I do?

The error can be a warning:

```text
Nov 30 21:04:28.268 WARN Syncing deposit contract block cache   est_blocks_remaining: initializing deposits, service: slot_notifier
```

or an error:

```text
ERRO Error updating deposit contract cache   error: Failed to get remote head and new block ranges: EndpointError(FarBehind), retry_millis: 60000, service: deposit_contract_rpc
```

This log indicates that your beacon node is downloading blocks and deposits
from your execution node. When the `est_blocks_remaining` is
`initializing_deposits`, your node is downloading deposit logs. It may stay in
this stage for several minutes. Once the deposits logs are finished
downloading, the `est_blocks_remaining` value will start decreasing.

It is perfectly normal to see this log when starting a node for the first time
or after being off for more than several minutes.

If this log continues appearing during operation, it means your execution client is still syncing and it cannot provide Lighthouse the information about the deposit contract yet. What you need to do is to make sure that the execution client is up and syncing. Once the execution client is synced, the error will disappear.

### <a name="bn-ee"></a> I see beacon logs showing `WARN: Execution engine called failed`, what should I do?

The `WARN Execution engine called failed` log is shown when the beacon node cannot reach the execution engine. When this warning occurs, it will be followed by a detailed message. A frequently encountered example of the error message is:

`error: HttpClient(url: http://127.0.0.1:8551/, kind: timeout, detail: operation timed out), service: exec`

which says `TimedOut` at the end of the message. This means that the execution engine has not responded in time to the beacon node. One option is to add the flags `--execution-timeout-multiplier 3` and `--disable-lock-timeouts` to the beacon node. However, if the error persists, it is worth digging further to find out the cause. There are a few reasons why this can occur:

1. The execution engine is not synced. Check the log of the execution engine to make sure that it is synced. If it is syncing, wait until it is synced and the error will disappear. You will see the beacon node logs `INFO Execution engine online` when it is synced.
1. The computer is overloaded. Check the CPU and RAM usage to see if it has overloaded. You can use `htop` to check for CPU and RAM usage.
1. Your SSD is slow. Check if your SSD is in "The Bad" list [here](https://gist.github.com/yorickdowne/f3a3e79a573bf35767cd002cc977b038). If your SSD is in "The Bad" list, it means it cannot keep in sync to the network and you may want to consider upgrading to a better SSD.

If the reason for the error message is caused by no. 1 above, you may want to look further. If the execution engine is out of sync suddenly, it is usually caused by ungraceful shutdown. The common causes for ungraceful shutdown are:

- Power outage. If power outages are an issue at your place, consider getting a UPS to avoid ungraceful shutdown of services.
- The service file is not stopped properly. To overcome this, make sure that the process is stopped properly, e.g., during client updates.
- Out of memory (oom) error. This can happen when the system memory usage has reached its maximum and causes the execution engine to be killed. To confirm that the error is due to oom, run `sudo dmesg -T | grep killed` to look for killed processes. If you are using geth as the execution client, a short term solution is to reduce the resources used. For example, you can reduce the cache by adding the flag `--cache 2048`. If the oom occurs rather frequently, a long term solution is to increase the memory capacity of the computer.

### <a name="bn-upcheck"></a> I see beacon logs showing `Error during execution engine upcheck`, what should I do?

An example of the full error is:

`ERRO Error during execution engine upcheck   error: HttpClient(url: http://127.0.0.1:8551/, kind: request, detail: error trying to connect: tcp connect error: Connection refused (os error 111)), service: exec`

Connection refused means the beacon node cannot reach the execution client. This could be due to the execution client is offline or the configuration is wrong. If the execution client is offline, run the execution engine and the error will disappear.

If it is a configuration issue, ensure that the execution engine can be reached. The standard endpoint to connect to the execution client is `--execution-endpoint http://localhost:8551`. If the execution client is on a different host, the endpoint to connect to it will change, e.g., `--execution-endpoint http://IP_address:8551` where `IP_address` is the IP of the execution client node (you may also need additional flags to be set). If it is using another port, the endpoint link needs to be changed accordingly. Once the execution client/beacon node is configured correctly, the error will disappear.

### <a name="bn-download-historical"></a> My beacon node is stuck at downloading historical block using checkpoint sync. What should I do?

After checkpoint forwards sync completes, the beacon node will start to download historical blocks. The log will look like:

```bash
INFO Downloading historical blocks           est_time: --, distance: 4524545 slots (89 weeks 5 days), service: slot_notifier
```

If the same log appears every minute and you do not see progress in downloading historical blocks, you can try one of the followings:

- Check the number of peers you are connected to. If you have low peers (less than 50), try to do port forwarding on the ports 9000 TCP/UDP and 9001 UDP to increase peer count.
- Restart the beacon node.

### <a name="bn-duplicate"></a> I proposed a block but the beacon node shows `could not publish message` with error `duplicate` as below, should I be worried?

```text
INFO Block from HTTP API already known`
WARN Could not publish message error: Duplicate, service: libp2p
```

This error usually happens when users are running mev-boost. The relay will publish the block on the network before returning it back to you. After the relay published the block on the network, it will propagate through nodes, and it happens quite often that your node will receive the block from your connected peers via gossip first, before getting the block from the relay, hence the message `duplicate`.

In short, it is nothing to worry about.

### <a name="bn-optimistic"></a> I see beacon node logs `Head is optimistic`, and I am missing attestations. What should I do?

The log looks like:

```text
WARN Head is optimistic       execution_block_hash: 0x47e7555f1d4215d1ad409b1ac188b008fcb286ed8f38d3a5e8078a0af6cbd6e1, info: chain not fully verified, block and attestation production disabled until execution engine syncs, service: slot_notifier
```

It means the beacon node will follow the chain, but it will not be able to attest or produce blocks. This is because the execution client is not synced, so the beacon chain cannot verify the authenticity of the chain head, hence the word `optimistic`. What you need to do is to make sure that the execution client is up and syncing. Once the execution client is synced, the error will disappear.

### <a name="bn-timeout"></a> My beacon node logs `CRIT Beacon block processing error error: ValidatorPubkeyCacheLockTimeout, service: beacon`, what should I do?

An example of the log is shown below:

```text
CRIT Beacon block processing error           error: ValidatorPubkeyCacheLockTimeout, service: beacon
WARN BlockProcessingFailure                  outcome: ValidatorPubkeyCacheLockTimeout, msg: unexpected condition in processing block.
```

A `Timeout` error suggests that the computer may be overloaded at the moment, for example, the execution client is still syncing. You may use the flag `--disable-lock-timeouts` to silence this error, although it will not fix the underlying slowness. Nevertheless, this is a relatively harmless log, and the error should go away once the resources used are back to normal.

### <a name="bn-missing-beacon"></a> My beacon node logs `WARN BlockProcessingFailure outcome: MissingBeaconBlock`, what should I do?

An example of the full log is shown below:

```text
WARN BlockProcessingFailure                  outcome: MissingBeaconBlock(0xbdba211f8d72029554e405d8e4906690dca807d1d7b1bc8c9b88d7970f1648bc), msg: unexpected condition in processing block.
```

`MissingBeaconBlock` suggests that the database has corrupted. You should wipe the database and use [Checkpoint Sync](./checkpoint-sync.md) to resync the beacon chain.

### <a name="bn-download-slow"></a> After checkpoint sync, the progress of `downloading historical blocks` is slow. Why?

This is a normal behaviour. Since [v4.1.0](https://github.com/sigp/lighthouse/releases/tag/v4.1.0), Lighthouse implements rate-limited backfill sync to mitigate validator performance issues after a checkpoint sync. This is not something to worry about since backfill sync / historical data is not required for staking. However, if you opt to sync the chain as fast as possible, you can add the flag `--disable-backfill-rate-limiting` to the beacon node.

### <a name="bn-http"></a> My beacon node logs `WARN Error processing HTTP API request`, what should I do?

This warning usually comes with an http error code. Some examples are given below:

1. The log shows:

    ```text
    WARN Error processing HTTP API request       method: GET, path: /eth/v1/validator/attestation_data, status: 500 Internal Server Error, elapsed: 305.65µs
    ```

    The error is `500 Internal Server Error`. This suggests that the execution client is not synced. Once the execution client is synced, the error will disappear.

1. The log shows:

    ```text
    WARN Error processing HTTP API request       method: POST, path: /eth/v1/validator/duties/attester/199565, status: 503 Service Unavailable, elapsed: 96.787µs
    ```

    The error is `503 Service Unavailable`. This means that the beacon node is still syncing. When this happens, the validator client will log:

    ```text
    ERRO Failed to download attester duties      err: FailedToDownloadAttesters("Some endpoints failed, num_failed: 2 http://localhost:5052/ => Unavailable(NotSynced), http://localhost:5052/ => RequestFailed(ServerMessage(ErrorMessage { code: 503, message: \"SERVICE_UNAVAILABLE: beacon node is syncing
    ```

    This means that the validator client is sending requests to the beacon node. However, as the beacon node is still syncing, it is therefore unable to fulfil the request. The error will disappear once the beacon node is synced.

### <a name="bn-fork-choice"></a> My beacon node logs `WARN Error signalling fork choice waiter`, what should I do?

An example of the full log is shown below:

```text
WARN Error signalling fork choice waiter slot: 6763073, error: ForkChoiceSignalOutOfOrder { current: Slot(6763074), latest: Slot(6763073) }, service: state_advance
```

This suggests that the computer resources are being overwhelmed. It could be due to high CPU usage or high disk I/O usage. This can happen, e.g., when the beacon node is downloading historical blocks, or when the execution client is syncing. The error will disappear when the resources used return to normal or when the node is synced.

### <a name="bn-queue-full"></a> My beacon node logs `ERRO Aggregate attestation queue full`, what should I do?

An example of the full log is shown below:

```text
ERRO Aggregate attestation queue full, queue_len: 4096, msg: the system has insufficient resources for load, module: network::beacon_processor:1542
```

This suggests that the computer resources are being overwhelmed. It could be due to high CPU usage or high disk I/O usage. This can happen, e.g., when the beacon node is downloading historical blocks, or when the execution client is syncing. The error will disappear when the resources used return to normal or when the node is synced.

### <a name="bn-deposit-cache"></a> My beacon node logs `WARN Failed to finalize deposit cache`, what should I do?

This is a known [bug](https://github.com/sigp/lighthouse/issues/3707) that will fix by itself.

### <a name="bn-blob"></a> My beacon node logs `WARN Could not verify blob sidecar for gossip`, what does it mean?

An example of the full log is shown below:

```text
Jun 07 23:05:12.170 WARN Could not verify blob sidecar for gossip. Ignoring the blob sidecar, commitment: 0xaa97…6f54, index: 1, root: 0x93b8…c47c, slot: 9248017, error: PastFinalizedSlot { blob_slot: Slot(9248017), finalized_slot: Slot(9248032) }, module: network::network_beacon_processor::gossip_methods:720
```

The `PastFinalizedSlot` indicates that the time at which the node received the blob has past the finalization period. This could be due to a peer sending an earlier blob. The log will be gone when Lighthouse eventually drops the peer.

## Validator

### <a name="vc-activation"></a> Why does it take so long for a validator to be activated?

After validators create their execution layer deposit transaction there are two waiting
periods before they can start producing blocks and attestations:

1. Waiting for the beacon chain to recognise the execution layer block containing the
   deposit (generally takes ~13.6 hours).
1. Waiting in the queue for validator activation.

Detailed answers below:

#### 1. Waiting for the beacon chain to detect the execution layer deposit

Since the beacon chain uses the execution layer for validator on-boarding, beacon chain
validators must listen to event logs from the deposit contract. Since the
latest blocks of the execution chain are vulnerable to re-orgs due to minor network
partitions, beacon nodes follow the execution chain at a distance of 2048 blocks
(~6.8 hours) (see
[`ETH1_FOLLOW_DISTANCE`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#process-deposit)).
This follow distance protects the beacon chain from on-boarding validators that
are likely to be removed due to an execution chain re-org.

Now we know there's a 6.8 hours delay before the beacon nodes even _consider_ an
execution layer block. Once they _are_ considering these blocks, there's a voting period
where beacon validators vote on which execution block hash to include in the beacon chain. This
period is defined as 64 epochs (~6.8 hours, see
[`ETH1_VOTING_PERIOD`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#time-parameters)).
During this voting period, each beacon block producer includes an
[`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#eth1data)
in their block which counts as a vote towards what that validator considers to
be the head of the execution chain at the start of the voting period (with respect
to `ETH1_FOLLOW_DISTANCE`, of course). You can see the exact voting logic
[here](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#eth1-data).

These two delays combined represent the time between an execution layer deposit being
included in an execution data vote and that validator appearing in the beacon chain.
The `ETH1_FOLLOW_DISTANCE` delay causes a minimum delay of ~6.8 hours and
`ETH1_VOTING_PERIOD` means that if a validator deposit happens just _before_
the start of a new voting period then they might not notice this delay at all.
However, if the validator deposit happens just _after_ the start of the new
voting period the validator might have to wait ~6.8 hours for next voting
period. In times of very severe network issues, the network may even fail
to vote in new execution layer blocks, thus stopping all new validator deposits and causing the wait to be longer.

#### 2. Waiting for a validator to be activated

If a validator has provided an invalid public key or signature, they will
_never_ be activated.
They will simply be forgotten by the beacon chain! But, if those parameters were
correct, once the execution layer delays have elapsed and the validator appears in the
beacon chain, there's _another_ delay before the validator becomes "active"
(canonical definition
[here](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#is_active_validator)) and can start producing blocks and attestations.

Firstly, the validator won't become active until their beacon chain balance is
equal to or greater than
[`MAX_EFFECTIVE_BALANCE`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#gwei-values)
(32 ETH on mainnet, usually 3.2 ETH on testnets). Once this balance is reached,
the validator must wait until the start of the next epoch (up to 6.4 minutes)
for the
[`process_registry_updates`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#registry-updates)
routine to run. This routine activates validators with respect to a [churn
limit](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#get_validator_churn_limit);
it will only allow the number of validators to increase (churn) by a certain
amount. If a new validator isn't within the churn limit from the front of the queue,
they will need to wait another epoch (6.4 minutes) for their next chance. This
repeats until the queue is cleared. The churn limit is summarised in the table below:

<div align="center" style="text-align: center;">

| Number of active validators | Validators activated per epoch | Validators activated per day |
|----------------|----|------|
| 327679 or less | 4  | 900  |
| 327680-393215  | 5  | 1125 |
| 393216-458751  | 6  | 1350 |
| 458752-524287  | 7  | 1575 |
| 524288-589823  | 8  | 1800 |
| 589824-655359  | 9  | 2025 |
| 655360-720895  | 10 | 2250 |
| 720896-786431  | 11 | 2475 |
| 786432-851967  | 12 | 2700 |
| 851968-917503  | 13 | 2925 |
| 917504-983039  | 14 | 3150 |
| 983040-1048575 | 15 | 3375 |

</div>

For example, the number of active validators on Mainnet is about 574000 on May 2023. This means that 8 validators can be activated per epoch or 1800 per day (it is noted that the same applies to the exit queue). If, for example, there are 9000 validators waiting to be activated, this means that the waiting time can take up to 5 days.

Once a validator has been activated, congratulations! It's time to
produce blocks and attestations!

### <a name="vc-redundancy"></a> Can I use redundancy in my staking setup?

You should **never** use duplicate/redundant validator keypairs or validator clients (i.e., don't
duplicate your JSON keystores and don't run `lighthouse vc` twice). This will lead to slashing.

However, there are some components which can be configured with redundancy. See the
[Redundancy](./redundancy.md) guide for more information.

### <a name="vc-missed-attestations"></a> I am missing attestations. Why?

The first thing is to ensure both consensus and execution clients are synced with the network. If they are synced, there may still be some issues with the node setup itself that is causing the missed attestations. Check the setup to ensure that:

- the clock is synced
- the computer has sufficient resources and is not overloaded
- the internet is working well
- you have sufficient peers

You can see more information on the [Ethstaker KB](https://ethstaker.gitbook.io/ethstaker-knowledge-base/help/missed-attestations).

Another cause for missing attestations is the block arriving late, or there are delays during block processing.

An example of the log: (debug logs can be found under `$datadir/beacon/logs`):

```text
Delayed head block, set_as_head_time_ms: 27, imported_time_ms: 168, attestable_delay_ms: 4209, available_delay_ms: 4186, execution_time_ms: 201, blob_delay_ms: 3815, observed_delay_ms: 3984, total_delay_ms: 4381, slot: 1886014, proposer_index: 733, block_root: 0xa7390baac88d50f1cbb5ad81691915f6402385a12521a670bbbd4cd5f8bf3934, service: beacon, module: beacon_chain::canonical_head:1441
```

The field to look for is `attestable_delay`, which defines the time when a block is ready for the validator to attest. If the `attestable_delay` is greater than 4s which has past the window of attestation, the attestation wil fail. In the above example, the delay is mostly caused by late block observed by the node, as shown in  `observed_delay`. The `observed_delay` is determined mostly by the proposer and partly by your networking setup (e.g., how long it took for the node to receive the block). Ideally,  `observed_delay` should be less than 3 seconds. In this example, the validator failed to attest the block due to the block arriving late.

Another example of log:

```
DEBG Delayed head block, set_as_head_time_ms: 22, imported_time_ms: 312, attestable_delay_ms: 7052, available_delay_ms: 6874, execution_time_ms: 4694, blob_delay_ms: 2159, observed_delay_ms: 2179, total_delay_ms: 7209, slot: 1885922, proposer_index: 606896, block_root: 0x9966df24d24e722d7133068186f0caa098428696e9f441ac416d0aca70cc0a23, service: beacon, module: beacon_chain::canonical_head:1441
/159.69.68.247/tcp/9000, service: libp2p, module: lighthouse_network::service:1811
```

In this example, we see that the `execution_time_ms` is 4694ms. The `execution_time_ms` is how long the node took to process the block. The `execution_time_ms` of larger than 1 second suggests that there is slowness in processing the block. If the `execution_time_ms` is high, it could be due to high CPU usage, high I/O disk usage or the clients are doing some background maintenance processes.

### <a name="vc-head-vote"></a> Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?

In general, it is unavoidable to have some penalties occasionally. This is particularly the case when you are assigned to attest on the first slot of an epoch and if the proposer of that slot releases the block late, then you will get penalised for missing the target and head votes. Your attestation performance does not only depend on your own setup, but also on everyone elses performance.

You could also check for the sync aggregate participation percentage on block explorers such as [beaconcha.in](https://beaconcha.in/). A low sync aggregate participation percentage (e.g., 60-70%) indicates that the block that you are assigned to attest to may be published late. As a result, your validator fails to correctly attest to the block.

Another possible reason for missing the head vote is due to a chain "reorg". A reorg can happen if the proposer publishes block `n` late, and the proposer of block `n+1` builds upon block `n-1` instead of `n`. This is called a "reorg". Due to the reorg, block `n` was never included in the chain.  If you are assigned to attest at slot `n`, it is possible you may still attest to block `n` despite most of the network recognizing the block as being late. In this case you will miss the head reward.

### <a name="vc-exit"></a> Can I submit a voluntary exit message without running a beacon node?

Yes. Beaconcha.in provides the tool to broadcast the message. You can create the voluntary exit message file with [ethdo](https://github.com/wealdtech/ethdo/releases/tag/v1.30.0) and submit the message via the [beaconcha.in](https://beaconcha.in/tools/broadcast) website. A guide on how to use `ethdo` to perform voluntary exit can be found [here](https://github.com/eth-educators/ethstaker-guides/blob/main/voluntary-exit.md).

It is also noted that you can submit your BLS-to-execution-change message to update your withdrawal credentials from type `0x00` to `0x01` using the same link.

If you would like to still use Lighthouse to submit the message, you will need to run a beacon node and an execution client. For the beacon node, you can use checkpoint sync to quickly sync the chain under a minute. On the other hand, the execution client can be syncing and _needs not be synced_. This implies that it is possible to broadcast a voluntary exit message within a short time by quickly spinning up a node.

### <a name="vc-resource"></a> Does increasing the number of validators increase the CPU and other computer resources used?

A computer with hardware specifications stated in the [Recommended System Requirements](./installation.md#recommended-system-requirements) can run hundreds validators with only marginal increase in CPU usage.

### <a name="vc-reimport"></a> I want to add new validators. Do I have to reimport the existing keys?

No. You can just import new validator keys to the destination directory. If the `validator_keys` folder contains existing keys, that's fine as well because Lighthouse will skip importing existing keys.

### <a name="vc-import"></a> Do I have to stop `lighthouse vc` when importing new validator keys?

Generally yes.

If you do not want to stop `lighthouse vc`, you can use the [key manager API](./api-vc-endpoints.md) to import keys.

### <a name="vc-delete"></a> How can I delete my validator once it is imported?

Lighthouse supports the [KeyManager API](https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/deleteKeys) to delete validators and remove them from the `validator_definitions.yml` file. To do so, start the validator client with the flag `--http` and call the API.

If you are looking to delete the validators in one node and import it to another, you can use the [validator-manager](./validator-manager-move.md) to move the validators across nodes without the hassle of deleting and importing the keys.

## Network, Monitoring and Maintenance

### <a name="net-peer"></a> I have a low peer count and it is not increasing

If you cannot find _ANY_ peers at all, it is likely that you have incorrect
network configuration settings. Ensure that the network you wish to connect to
is correct (the beacon node outputs the network it is connecting to in the
initial boot-up log lines). On top of this, ensure that you are not using the
same `datadir` as a previous network, i.e., if you have been running the
`Holesky` testnet and are now trying to join a new network but using the same
`datadir` (the `datadir` is also printed out in the beacon node's logs on
boot-up).

If you find yourself with a low peer count and it's not reaching the target you
expect, there are a few things to check on:

1. Ensure that port forward was correctly set up as described [here](./advanced_networking.md#nat-traversal-port-forwarding).

    To check that the ports are forwarded, run the command:

    ```bash
    curl http://localhost:5052/lighthouse/nat
    ```

    It should return `{"data":true}`. If it returns `{"data":false}`, you may want to double check if the port forward was correctly set up.

    If the ports are open, you should have incoming peers. To check that you have incoming peers, run the command:

    ```bash
    curl localhost:5052/lighthouse/peers | jq '.[] | select(.peer_info.connection_direction=="Incoming")'
    ```

    If you have incoming peers, it should return a lot of data containing information of peers. If the response is empty, it means that you have no incoming peers and there the ports are not open. You may want to double check if the port forward was correctly set up.

1. Check that you do not lower the number of peers using the flag `--target-peers`. The default is 100. A lower value set will lower the maximum number of peers your node can connect to, which may potentially interrupt the validator performance. We recommend users to leave the `--target peers` untouched to keep a diverse set of peers.

1. Ensure that you have a quality router for the internet connection. For example, if you connect the router to many devices including the node, it may be possible that the router cannot handle all routing tasks, hence struggling to keep up the number of peers. Therefore, using a quality router for the node is important to keep a healthy number of peers.

### <a name="net-update"></a> How do I update lighthouse?

If you are updating to new release binaries, it will be the same process as described [here.](./installation-binaries.md)

If you are updating by rebuilding from source, see [here.](./installation-source.md#update-lighthouse)

If you are running the docker image provided by Sigma Prime on Dockerhub, you can update to specific versions, for example:

```bash
docker pull sigp/lighthouse:v1.0.0
```

If you are building a docker image, the process will be similar to the one described [here.](./docker.md#building-the-docker-image)
You just need to make sure the code you have checked out is up to date.

### <a name="net-port-forwarding"></a> Do I need to set up any port mappings (port forwarding)?

It is not strictly required to open any ports for Lighthouse to connect and
participate in the network. Lighthouse should work out-of-the-box. However, if
your node is not publicly accessible (you are behind a NAT or router that has
not been configured to allow access to Lighthouse ports) you will only be able
to reach peers who have a set up that is publicly accessible.

There are a number of undesired consequences of not making your Lighthouse node
publicly accessible.

Firstly, it will make it more difficult for your node to find peers, as your
node will not be added to the global DHT and other peers will not be able
to initiate connections with you.
Secondly, the peers in your peer store are more likely to end connections with
you and be less performant as these peers will likely be overloaded with
subscribing peers. The reason being, that peers that have correct port
forwarding (publicly accessible) are in higher demand than regular peers as other nodes behind NAT's
will also be looking for these peers.
Finally, not making your node publicly accessible degrades the overall network, making it more difficult for other
peers to join and degrades the overall connectivity of the global network.

For these reasons, we recommend that you make your node publicly accessible.

Lighthouse supports UPnP. If you are behind a NAT with a router that supports
UPnP, you can simply ensure UPnP is enabled (Lighthouse will inform you in its
initial logs if a route has been established). You can also manually [set up port mappings/port forwarding](./advanced_networking.md#how-to-open-ports) in your router to your local Lighthouse instance. By default,
Lighthouse uses port 9000 for both TCP and UDP, and optionally 9001 UDP for QUIC support.
Opening these ports will make your Lighthouse node maximally contactable.

### <a name="net-monitor"></a> How can I monitor my validators?

Apart from using block explorers, you may use the "Validator Monitor" built into Lighthouse which
provides logging and Prometheus/Grafana metrics for individual validators. See [Validator
Monitoring](./validator-monitoring.md) for more information. Lighthouse has also developed Lighthouse UI (Siren) to monitor performance, see [Lighthouse UI (Siren)](./lighthouse-ui.md).

### <a name="net-bn-vc"></a> My beacon node and validator client are on different servers. How can I point the validator client to the beacon node?

The setting on the beacon node is the same for both cases below. In the beacon node, specify `lighthouse bn --http-address local_IP` so that the beacon node is listening on the local network rather than `localhost`. You can find the `local_IP` by running the command `hostname -I | awk '{print $1}'` on the server running the beacon node.

1. If the beacon node and validator clients are on different servers _in the same network_, the setting in the validator client is as follows:

   Use the flag `--beacon-nodes` to point to the beacon node. For example, `lighthouse vc --beacon-nodes http://local_IP:5052` where `local_IP` is the local IP address of the beacon node and `5052` is the default `http-port` of the beacon node.

   If you have firewall setup, e.g., `ufw`, you will need to allow port 5052 (assuming that the default port is used) with `sudo ufw allow 5052`. Note: this will allow all IP addresses to access the HTTP API of the beacon node. If you are on an untrusted network (e.g., a university or public WiFi) or the host is exposed to the internet, use apply IP-address filtering as described later in this section.

   You can test that the setup is working with by running the following command on the validator client host:

   ```bash
   curl "http://local_IP:5052/eth/v1/node/version"
   ```

   You can refer to [Redundancy](./redundancy.md) for more information.

2. If the beacon node and validator clients are on different servers _and different networks_, it is necessary to perform port forwarding of the SSH port (e.g., the default port 22) on the router, and also allow firewall on the SSH port. The connection can be established via port forwarding on the router.

      In the validator client, use the flag `--beacon-nodes` to point to the beacon node. However, since the beacon node and the validator client are on different networks, the IP address to use is the public IP address of the beacon node, i.e., `lighthouse vc --beacon-nodes http://public_IP:5052`. You can get the public IP address of the beacon node by running the command `dig +short myip.opendns.com @resolver1.opendns.com` on the server running the beacon node.

      Additionally, port forwarding of port 5052 on the router connected to the beacon node is required for the vc to connect to the bn. To do port forwarding, refer to [how to open ports](./advanced_networking.md#how-to-open-ports).

      If you have firewall setup, e.g., `ufw`, you will need to allow connections to port 5052 (assuming that the default port is used). Since the beacon node HTTP/HTTPS API is public-facing (i.e., the 5052 port is now exposed to the internet due to port forwarding), we strongly recommend users to apply IP-address filtering to the BN/VC connection from malicious actors. This can be done using the command:

      ```bash
      sudo ufw allow from vc_IP_address proto tcp to any port 5052
      ```

      where `vc_IP_address` is the public IP address of the validator client. The command will only allow connections to the beacon node from the validator client IP address to prevent malicious attacks on the beacon node over the internet.

It is also worth noting that the `--beacon-nodes` flag can also be used for redundancy of beacon nodes. For example, let's say you have a beacon node and a validator client running on the same host, and a second beacon node on another server as a backup. In this case, you can use `lighthouse vc --beacon-nodes http://localhost:5052, http://IP-address:5052` on the validator client.

### <a name="net-ip"></a> Should I do anything to the beacon node or validator client settings if I have a relocation of the node / change of IP address?

No. Lighthouse will auto-detect the change and update your Ethereum Node Record (ENR). You just need to make sure you are not manually setting the ENR with `--enr-address` (which, for common use cases, this flag is not used).

### <a name="net-port"></a> How to change the TCP/UDP port 9000 that Lighthouse listens on?

Use the flag `--port <PORT>` in the beacon node. This flag can be useful when you are running two beacon nodes at the same time. You can leave one beacon node as the default port 9000, and configure the second beacon node to listen on, e.g., `--port 9100`.
Since V4.5.0, Lighthouse supports QUIC and by default will use the value of `--port` + 1 to listen via UDP (default `9001`).
This can be configured by using the flag `--quic-port`. Refer to [Advanced Networking](./advanced_networking.md#nat-traversal-port-forwarding) for more information.

### <a name="net-subnet"></a> Lighthouse `v4.3.0` introduces a change where a node will subscribe to only 2 subnets in total. I am worried that this will impact my validators return

Previously, having more validators means subscribing to more subnets. Since the change, a node will now only subscribe to 2 subnets in total. This will bring about significant reductions in bandwidth for nodes with multiple validators.

While subscribing to more subnets can ensure you have peers on a wider range of subnets, these subscriptions consume resources and bandwidth. This does not significantly increase the performance of the node, however it does benefit other nodes on the network.

If you would still like to subscribe to all subnets, you can use the flag `subscribe-all-subnets`. This may improve the block rewards by 1-5%, though it comes at the cost of a much higher bandwidth requirement.

### <a name="net-quic"></a> How to know how many of my peers are connected via QUIC?

With `--metrics` enabled in the beacon node, the [Grafana Network dashboard](https://github.com/sigp/lighthouse-metrics/blob/master/dashboards/Network.json) displays the connected by transport, which will show the number of peers connected via QUIC.

Alternatively, you can find the number of peers connected via QUIC manually using:

```bash
 curl -s "http://localhost:5054/metrics" | grep 'transport="quic"'
```

A response example is:

```text
libp2p_peers_multi{direction="inbound",transport="quic"} 27
libp2p_peers_multi{direction="none",transport="quic"} 0
libp2p_peers_multi{direction="outbound",transport="quic"} 9
```

which shows that there are a total of 36 peers connected via QUIC.

## Miscellaneous

### <a name="misc-slashing"></a> What should I do if I lose my slashing protection database?

See [here](./slashing-protection.md#misplaced-slashing-database).

### <a name="misc-compile"></a> I can't compile lighthouse

See [here.](./installation-source.md#troubleshooting)

### <a name="misc-version"></a> How do I check the version of Lighthouse that is running?

If you build Lighthouse from source, run `lighthouse --version`. Example of output:

```bash
Lighthouse v4.1.0-693886b
BLS library: blst-modern
SHA256 hardware acceleration: false
Allocator: jemalloc
Specs: mainnet (true), minimal (false), gnosis (true)
```

If you download the binary file, navigate to the location of the directory, for example, the binary file is in `/usr/local/bin`, run `/usr/local/bin/lighthouse --version`, the example of output is the same as above.

Alternatively, if you have Lighthouse running, on the same computer, you can run:

```bash
curl "http://127.0.0.1:5052/eth/v1/node/version"
```

Example of output:

```bash
{"data":{"version":"Lighthouse/v4.1.0-693886b/x86_64-linux"}}
```

which says that the version is v4.1.0.

### <a name="misc-prune"></a> Does Lighthouse have pruning function like the execution client to save disk space?

Yes, Lighthouse supports [state pruning](./database-migrations.md#how-to-prune-historic-states) which can help to save disk space.

### <a name="misc-freezer"></a> Can I use a HDD for the freezer database and only have the hot db on SSD?

Yes, you can do so by using the flag `--freezer-dir /path/to/freezer_db` in the beacon node.

### <a name="misc-timestamp"></a> Can Lighthouse log in local timestamp instead of UTC?

The reason why Lighthouse logs in UTC is due to the dependency on an upstream library that is [yet to be resolved](https://github.com/sigp/lighthouse/issues/3130). Alternatively, using the flag `disable-log-timestamp` in combination with systemd will suppress the UTC timestamps and print the logs in local timestamps.

### <a name="misc-full"></a> My hard disk is full and my validator is down. What should I do?

A quick way to get the validator back online is by removing the Lighthouse beacon node database and resync Lighthouse using checkpoint sync. A guide to do this can be found in the [Lighthouse Discord server](https://discord.com/channels/605577013327167508/605577013331361793/1019755522985050142). With some free space left, you will then be able to prune the execution client database to free up more space.
