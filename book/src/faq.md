# Frequently Asked Questions

## [Beacon Node](#beacon-node-1)
- [I see a warning about "Syncing deposit contract block cache" or an error about "updating deposit contract cache", what should I do?](#bn-deposit-contract)
- [I see beacon logs showing `WARN: Execution engine called failed`, what should I do?](#bn-ee)
- [My beacon node is stuck at downloading historical block using checkpoint sync. What should I do?](#bn-download-historical)
- [I proposed a block but the beacon node shows `could not publish message` with error `duplicate` as below, should I be worried?](#bn-duplicate)
- [I see beacon node logs `Head is optimistic` and I am missing attestations. What should I do?](#bn-optimistic)
- [My beacon node logs `CRIT Beacon block processing error error: ValidatorPubkeyCacheLockTimeout`, what should I do?](#bn-timeout)
- [My beacon node logs `WARN BlockProcessingFailure outcome: MissingBeaconBlock`, what should I do?](#bn-missing-beacon)
- [After checkpoint sync, the progress of `downloading historical blocks` is slow. Why?](#bn-download-slow)
- [My beacon node logs `WARN Error processing HTTP API request`, what should I do?](#bn-http)

## [Validator](#validator-1)
- [Why does it take so long for a validator to be activated?](#vc-activation)
- [Can I use redundancy in my staking setup?](#vc-redundancy)
- [I am missing attestations. Why?](#vc-missed-attestations)
- [Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?](#vc-head-vote)
- [Can I submit a voluntary exit message without a beacon node?](#vc-exit)
- [Does increasing the number of validators increase the CPU and other computer resources used?](#vc-resource)
- [I want to add new validators. Do I have to reimport the existing keys?](#vc-reimport)
- [Do I have to stop `lighthouse vc` the when importing new validator keys?](#vc-import)


## [Network, Monitoring and Maintenance](#network-monitoring-and-maintenance-1)
- [I have a low peer count and it is not increasing](#net-peer)
- [How do I update lighthouse?](#net-update)
- [Do I need to set up any port mappings (port forwarding)?](#net-port-forwarding)
- [How can I monitor my validators?](#net-monitor)
- [My beacon node and validator client are on different servers. How can I point the validator client to the beacon node?](#net-bn-vc)
- [Should I do anything to the beacon node or validator client settings if I have a relocation of the node / change of IP address?](#net-ip)
- [How to change the TCP/UDP port 9000 that Lighthouse listens on?](#net-port)


## [Miscellaneous](#miscellaneous-1)
- [What should I do if I lose my slashing protection database?](#misc-slashing)
- [I can't compile lighthouse](#misc-compile)
- [How do I check the version of Lighthouse that is running?](#misc-version)
- [Does Lighthouse have pruning function like the execution client to save disk space?](#misc-prune)
- [Can I use a HDD for the freezer database and only have the hot db on SSD?](#misc-freezer)

## Beacon Node



### <a name="bn-deposit-contract"></a> I see a warning about "Syncing deposit contract block cache" or an error about "updating deposit contract cache", what should I do?

The error can be a warning:

```
Nov 30 21:04:28.268 WARN Syncing deposit contract block cache   est_blocks_remaining: initializing deposits, service: slot_notifier
```

or an error:

```
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

`error: Reqwest(reqwest::Error { kind: Request, url: Url { scheme: "http", cannot_be_a_base: false, username: "", password: None, host: Some(Ipv4(127.0.0.1)), port: Some(8551), path: "/", query: None, fragment: None }, source: TimedOut }), service: exec`

which says `TimedOut` at the end of the message. This means that the execution engine has not responded in time to the beacon node. One option is to add the flag `--execution-timeout-multiplier 3` to the beacon node. However, if the error persists, it is worth digging further to find out the cause. There are a few reasons why this can occur:
1. The execution engine is not synced. Check the log of the execution engine to make sure that it is synced. If it is syncing, wait until it is synced and the error will disappear. You will see the beacon node logs `INFO Execution engine online` when it is synced. 
1. The computer is overloaded. Check the CPU and RAM usage to see if it has overloaded. You can use `htop` to check for CPU and RAM usage.
1. Your SSD is slow. Check if your SSD is in "The Bad" list [here](https://gist.github.com/yorickdowne/f3a3e79a573bf35767cd002cc977b038). If your SSD is in "The Bad" list, it means it cannot keep in sync to the network and you may want to consider upgrading to a better SSD.

If the reason for the error message is caused by no. 1 above, you may want to look further. If the execution engine is out of sync suddenly, it is usually caused by ungraceful shutdown. The common causes for ungraceful shutdown are:
- Power outage. If power outages are an issue at your place, consider getting a UPS to avoid ungraceful shutdown of services. 
- The service file is not stopped properly. To overcome this, make sure that the process is stopped properly, e.g., during client updates. 
- Out of memory (oom) error. This can happen when the system memory usage has reached its maximum and causes the execution engine to be killed. When this occurs, the log file will show `Main process exited, code=killed, status=9/KILL`.  You can also run `sudo journalctl -a --since "18 hours ago" | grep -i "killed process` to confirm that the execution client has been killed due to oom. If you are using geth as the execution client, a short term solution is to reduce the resources used. For example, you can reduce the cache by adding the flag `--cache 2048`. If the oom occurs rather frequently, a long term solution is to increase the memory capacity of the computer.

### <a name="bn-download-historical"></a> My beacon node is stuck at downloading historical block using checkpoint sync. What should I do?

After checkpoint forwards sync completes, the beacon node will start to download historical blocks. The log will look like:

```bash
INFO Downloading historical blocks           est_time: --, distance: 4524545 slots (89 weeks 5 days), service: slot_notifier
```

If the same log appears every minute and you do not see progress in downloading historical blocks, you can try one of the followings:
 
   - Check the number of peers you are connected to. If you have low peers (less than 50), try to do port forwarding on the port 9000 TCP/UDP to increase peer count.
   - Restart the beacon node.


### <a name="bn-duplicate"></a> I proposed a block but the beacon node shows `could not publish message` with error `duplicate` as below, should I be worried?

```
INFO Block from HTTP API already known`
WARN Could not publish message error: Duplicate, service: libp2p
```

This error usually happens when users are running mev-boost. The relay will publish the block on the network before returning it back to you. After the relay published the block on the network, it will propagate through nodes, and it happens quite often that your node will receive the block from your connected peers via gossip first, before getting the block from the relay, hence the message `duplicate`. 

In short, it is nothing to worry about.

### <a name="bn-optimistic"></a> I see beacon node logs `Head is optimistic`, and I am missing attestations. What should I do?

The log looks like:

```
WARN Head is optimistic       execution_block_hash: 0x47e7555f1d4215d1ad409b1ac188b008fcb286ed8f38d3a5e8078a0af6cbd6e1, info: chain not fully verified, block and attestation production disabled until execution engine syncs, service: slot_notifier
```

It means the beacon node will follow the chain, but it will not be able to attest or produce blocks. This is because the execution client is not synced, so the beacon chain cannot verify the authenticity of the chain head, hence the word `optimistic`. What you need to do is to make sure that the execution client is up and syncing. Once the execution client is synced, the error will disappear.

### <a name="bn-timeout"></a> My beacon node logs `CRIT Beacon block processing error error: ValidatorPubkeyCacheLockTimeout, service: beacon`, what should I do? 

An example of the log is shown below:

```
CRIT Beacon block processing error           error: ValidatorPubkeyCacheLockTimeout, service: beacon
WARN BlockProcessingFailure                  outcome: ValidatorPubkeyCacheLockTimeout, msg: unexpected condition in processing block.
```

A `Timeout` error suggests that the computer may be overloaded at the moment, for example, the execution client is still syncing. You may use the flag `--disable-lock-timeouts` to silence this error, although it will not fix the underlying slowness. Nevertheless, this is a relatively harmless log, and the error should go away once the resources used are back to normal. 

### <a name="bn-missing-beacon"></a> My beacon node logs `WARN BlockProcessingFailure outcome: MissingBeaconBlock`, what should I do?

An example of the full log is shown below:

```
WARN BlockProcessingFailure                  outcome: MissingBeaconBlock(0xbdba211f8d72029554e405d8e4906690dca807d1d7b1bc8c9b88d7970f1648bc), msg: unexpected condition in processing block.
```

`MissingBeaconBlock` suggests that the database has corrupted. You should wipe the database and use [Checkpoint Sync](./checkpoint-sync.md) to resync the beacon chain. 

### <a name="bn-download-slow"></a> After checkpoint sync, the progress of `downloading historical blocks` is slow. Why?

This is a normal behaviour. Since [v4.1.0](https://github.com/sigp/lighthouse/releases/tag/v4.1.0), Lighthouse implements rate-limited backfill sync to mitigate validator performance issues after a checkpoint sync. This is not something to worry about since backfill sync / historical data is not required for staking. However, if you opt to sync the chain as fast as possible, you can add the flag `--disable-backfill-rate-limiting` to the beacon node.

### <a name="bn-http"></a> My beacon node logs `WARN Error processing HTTP API request`, what should I do?

This warning usually comes with an http error code. Some examples are given below:

1. The log shows:

```
WARN Error processing HTTP API request       method: GET, path: /eth/v1/validator/attestation_data, status: 500 Internal Server Error, elapsed: 305.65µs
```

The error is `500 Internal Server Error`. This suggests that the execution client is not synced. Once the execution client is synced, the error will disappear.

2. The log shows:

```
WARN Error processing HTTP API request       method: POST, path: /eth/v1/validator/duties/attester/199565, status: 503 Service Unavailable, elapsed: 96.787µs
```

The error is `503 Service Unavailable`. This means that the beacon node is still syncing. When this happens, the validator client will log:

```
ERRO Failed to download attester duties      err: FailedToDownloadAttesters("Some endpoints failed, num_failed: 2 http://localhost:5052/ => Unavailable(NotSynced), http://localhost:5052/ => RequestFailed(ServerMessage(ErrorMessage { code: 503, message: \"SERVICE_UNAVAILABLE: beacon node is syncing
```

This means that the validator client is sending requests to the beacon node. However, as the beacon node is still syncing, it is therefore unable to fulfil the request. The error will disappear once the beacon node is synced. 

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

| Number of active validators           | Validators activated per epoch     | Validators activated per day | 
|-------------------|--------------------------------------------|----|
| 327679 or less     | 4    | 900  | 
| 327680-393215            |  5   | 1125 |
| 393216-458751 | 6 | 1350
| 458752-524287 | 7  | 1575
| 524288-589823 | 8| 1800 |
| 589824-655359 | 9| 2025 |
| 655360-720895 | 10 | 2250|
| 720896-786431 | 11 | 2475 |
| 786432-851967 | 12 | 2700 |
| 851968-917503 | 13 | 2925 |
| 917504-983039 | 14 | 3150 |
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

You can see more information on the [Ethstaker KB](https://ethstaker.gitbook.io/ethstaker-knowledge-base/help/missed-attestations). Once the above points are good, missing attestation should be a rare occurrence. 

### <a name="vc-head-vote"></a> Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?

In general, it is unavoidable to have some penalties occasionally. This is particularly the case when you are assigned to attest on the first slot of an epoch and if the proposer of that slot releases the block late, then you will get penalised for missing the target and head votes. Your attestation performance does not only depend on your own setup, but also on everyone elses performance.

### <a name="vc-exit"></a> Can I submit a voluntary exit message without running a beacon node?

Yes. Beaconcha.in provides the tool to broadcast the message. You can create the voluntary exit message file with [ethdo](https://github.com/wealdtech/ethdo/releases/tag/v1.30.0) and submit the message via the [beaconcha.in](https://beaconcha.in/tools/broadcast) website. A guide on how to use `ethdo` to perform voluntary exit can be found [here](https://github.com/eth-educators/ethstaker-guides/blob/main/voluntary-exit.md).

It is also noted that you can submit your BLS-to-execution-change message to update your withdrawal credentials from type `0x00` to `0x01` using the same link.

If you would like to still use Lighthouse to submit the message, you will need to run a beacon node and an execution client. For the beacon node, you can use checkpoint sync to quickly sync the chain under a minute. On the other hand, the execution client can be syncing and *needs not be synced*. This implies that it is possible to broadcast a voluntary exit message within a short time by quickly spinning up a node.

### <a name="vc-resource"></a> Does increasing the number of validators increase the CPU and other computer resources used?

A computer with hardware specifications stated in the [Recommended System Requirements](./installation.md#recommended-system-requirements) can run hundreds validators with only marginal increase in cpu usage. When validators are active, there is a bit of an increase in resources used from validators 0-64, because you end up subscribed to more subnets. After that, the increase in resources plateaus when the number of validators go from 64 to ~500.

### <a name="vc-reimport"></a> I want to add new validators. Do I have to reimport the existing keys?

No. You can just import new validator keys to the destination directory. If the `validator_keys` folder contains existing keys, that's fine as well because Lighthouse will skip importing existing keys.

### <a name="vc-import"></a> Do I have to stop `lighthouse vc` when importing new validator keys?

Generally yes.

If you do not want to stop `lighthouse vc`, you can use the [key manager API](./api-vc-endpoints.md) to import keys.

## Network, Monitoring and Maintenance

### <a name="net-peer"></a> I have a low peer count and it is not increasing

If you cannot find *ANY* peers at all, it is likely that you have incorrect
network configuration settings. Ensure that the network you wish to connect to
is correct (the beacon node outputs the network it is connecting to in the
initial boot-up log lines). On top of this, ensure that you are not using the
same `datadir` as a previous network, i.e., if you have been running the
`Goerli` testnet and are now trying to join a new network but using the same
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

2. Check that you do not lower the number of peers using the flag `--target-peers`. The default is 80. A lower value set will lower the maximum number of peers your node can connect to, which may potentially interrupt the validator performance. We recommend users to leave the `--target peers` untouched to keep a diverse set of peers. 

3. Ensure that you have a quality router for the internet connection. For example, if you connect the router to many devices including the node, it may be possible that the router cannot handle all routing tasks, hence struggling to keep up the number of peers. Therefore, using a quality router for the node is important to keep a healthy number of peers.


### <a name="net-update"></a> How do I update lighthouse?

If you are updating to new release binaries, it will be the same process as described [here.](./installation-binaries.md)

If you are updating by rebuilding from source, see [here.](./installation-source.md#update-lighthouse)

If you are running the docker image provided by Sigma Prime on Dockerhub, you can update to specific versions, for example:

```bash
$ docker pull sigp/lighthouse:v1.0.0
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
Lighthouse uses port 9000 for both TCP and UDP. Opening both these ports will
make your Lighthouse node maximally contactable.

### <a name="net-monitor"></a> How can I monitor my validators?

Apart from using block explorers, you may use the "Validator Monitor" built into Lighthouse which
provides logging and Prometheus/Grafana metrics for individual validators. See [Validator
Monitoring](./validator-monitoring.md) for more information. Lighthouse has also developed Lighthouse UI (Siren) to monitor performance, see [Lighthouse UI (Siren)](./lighthouse-ui.md).

### <a name="net-bn-vc"></a> My beacon node and validator client are on different servers. How can I point the validator client to the beacon node?

The settings are as follows:

1. On the beacon node: 
   
   Specify `lighthouse bn --http-address local_IP` so that the beacon node is listening on the local network rather than on the `localhost`. 

1. On the validator client:

   Use the flag `--beacon-nodes` to point to the beacon node. For example, `lighthouse vc --beacon-nodes http://local_IP:5052` where `local_IP` is the local IP address of the beacon node and `5052` is the default `http-port` of the beacon node.

   You can test that the setup is working with by running the following command on the validator client host:

   ```bash
   curl "http://local_IP:5052/eth/v1/node/version"
   ```

   You can refer to [Redundancy](./redundancy.md) for more information.
   
   It is also worth noting that the `--beacon-nodes` flag can also be used for redundancy of beacon nodes. For example, let's say you have a beacon node and a validator client running on the same host, and a second beacon node on another server as a backup. In this case, you can use `lighthouse vc --beacon-nodes http://localhost:5052, http://local_IP:5052` on the validator client.

### <a name="net-ip"></a> Should I do anything to the beacon node or validator client settings if I have a relocation of the node / change of IP address?
No. Lighthouse will auto-detect the change and update your Ethereum Node Record (ENR). You just need to make sure you are not manually setting the ENR with `--enr-address` (which, for common use cases, this flag is not used).

### <a name="net-port"></a> How to change the TCP/UDP port 9000 that Lighthouse listens on?
Use the flag ```--port <PORT>``` in the beacon node. This flag can be useful when you are running two beacon nodes at the same time. You can leave one beacon node as the default port 9000, and configure the second beacon node to listen on, e.g., ```--port 9001```.

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

There is no pruning of Lighthouse database for now. However, since v4.2.0, a feature to only sync back to the weak subjectivity point (approximately 5 months) when syncing via a checkpoint sync was added. This will help to save disk space since the previous behaviour will sync back to the genesis by default. 

### <a name="misc-freezer"></a> Can I use a HDD for the freezer database and only have the hot db on SSD?

Yes, you can do so by using the flag `--freezer-dir /path/to/freezer_db` in the beacon node.
























