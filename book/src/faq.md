# Frequently Asked Questions

- [Why does it take so long for a validator to be activated?](#why-does-it-take-so-long-for-a-validator-to-be-activated)
- [Do I need to set up any port mappings?](#do-i-need-to-set-up-any-port-mappings)
- [I have a low peer count and it is not increasing](#i-have-a-low-peer-count-and-it-is-not-increasing)
- [What should I do if I lose my slashing protection database?](#what-should-i-do-if-i-lose-my-slashing-protection-database)
- [How do I update lighthouse?](#how-do-i-update-lighthouse)
- [I can't compile lighthouse](#i-cant-compile-lighthouse)
- [What is "Syncing deposit contract block cache"?](#what-is-syncing-deposit-contract-block-cache)
- [Can I use redundancy in my staking setup?](#can-i-use-redundancy-in-my-staking-setup)
- [How can I monitor my validators?](#how-can-i-monitor-my-validators)
- [I see beacon logs showing `WARN: Execution engine called failed`, what should I do?](#i-see-beacon-logs-showing-warn-execution-engine-called-failed-what-should-i-do)
- [How do I check or update my withdrawal credentials?](#how-do-i-check-or-update-my-withdrawal-credentials)
- [I am missing attestations. Why?](#i-am-missing-attestations-why)
- [Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?](#sometimes-i-miss-the-attestation-head-vote-resulting-in-penalty-is-this-normal)
- [My beacon node is stuck at downloading historical block using checkpoing sync. What can I do?](#my-beacon-node-is-stuck-at-downloading-historical-block-using-checkpoing-sync-what-can-i-do)

### Why does it take so long for a validator to be activated?

After validators create their execution layer deposit transaction there are two waiting
periods before they can start producing blocks and attestations:

1. Waiting for the beacon chain to recognise the execution layer block containing the
   deposit (generally 4 to 7.4 hours).
1. Waiting in the queue for validator activation (generally 6.4 minutes for
   every 4 validators in the queue).

Detailed answers below:

#### 1. Waiting for the beacon chain to detect the execution layer deposit

Since the beacon chain uses the execution layer for validator on-boarding, beacon chain
validators must listen to event logs from the deposit contract. Since the
latest blocks of the execution chain are vulnerable to re-orgs due to minor network
partitions, beacon nodes follow the execution chain at a distance of 1,024 blocks
(~4 hours) (see
[`ETH1_FOLLOW_DISTANCE`](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/validator.md#misc)).
This follow distance protects the beacon chain from on-boarding validators that
are likely to be removed due to an execution chain re-org.

Now we know there's a 4 hours delay before the beacon nodes even _consider_ an
execution layer block. Once they _are_ considering these blocks, there's a voting period
where beacon validators vote on which execution block hash to include in the beacon chain. This
period is defined as 32 epochs (~3.4 hours, see
[`ETH1_VOTING_PERIOD`](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#time-parameters)).
During this voting period, each beacon block producer includes an
[`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#eth1data)
in their block which counts as a vote towards what that validator considers to
be the head of the execution chain at the start of the voting period (with respect
to `ETH1_FOLLOW_DISTANCE`, of course). You can see the exact voting logic
[here](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/validator.md#eth1-data).

These two delays combined represent the time between an execution layer deposit being
included in an execution data vote and that validator appearing in the beacon chain.
The `ETH1_FOLLOW_DISTANCE` delay causes a minimum delay of ~4 hours and
`ETH1_VOTING_PERIOD` means that if a validator deposit happens just _before_
the start of a new voting period then they might not notice this delay at all.
However, if the validator deposit happens just _after_ the start of the new
voting period the validator might have to wait ~3.4 hours for next voting
period. In times of very, very severe network issues, the network may even fail
to vote in new execution layer blocks, stopping all new validator deposits!

#### 2. Waiting for a validator to be activated

If a validator has provided an invalid public key or signature, they will
_never_ be activated.
They will simply be forgotten by the beacon chain! But, if those parameters were
correct, once the execution layer delays have elapsed and the validator appears in the
beacon chain, there's _another_ delay before the validator becomes "active"
(canonical definition
[here](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#is_active_validator)) and can start producing blocks and attestations.

Firstly, the validator won't become active until their beacon chain balance is
equal to or greater than
[`MAX_EFFECTIVE_BALANCE`](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#gwei-values)
(32 ETH on mainnet, usually 3.2 ETH on testnets). Once this balance is reached,
the validator must wait until the start of the next epoch (up to 6.4 minutes)
for the
[`process_registry_updates`](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#registry-updates)
routine to run. This routine activates validators with respect to a [churn
limit](https://github.com/ethereum/consensus-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#get_validator_churn_limit);
it will only allow the number of validators to increase (churn) by a certain
amount. Up until there are about 330,000 validators this churn limit is set to
4 and it starts to very slowly increase as the number of validators increases
from there.

If a new validator isn't within the churn limit from the front of the queue,
they will need to wait another epoch (6.4 minutes) for their next chance. This
repeats until the queue is cleared.

Once a validator has been activated, there's no more waiting! It's time to
produce blocks and attestations!

### Do I need to set up any port mappings?

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
UPnP you can simply ensure UPnP is enabled (Lighthouse will inform you in its
initial logs if a route has been established). You can also manually set up
port mappings in your router to your local Lighthouse instance. By default,
Lighthouse uses port 9000 for both TCP and UDP. Opening both these ports will
make your Lighthouse node maximally contactable.

### I have a low peer count and it is not increasing

If you cannot find *ANY* peers at all. It is likely that you have incorrect
testnet configuration settings. Ensure that the network you wish to connect to
is correct (the beacon node outputs the network it is connecting to in the
initial boot-up log lines). On top of this, ensure that you are not using the
same `datadir` as a previous network. I.e if you have been running the
`prater` testnet and are now trying to join a new testnet but using the same
`datadir` (the `datadir` is also printed out in the beacon node's logs on
boot-up).

If you find yourself with a low peer count and it's not reaching the target you
expect. Try setting up the correct port forwards as described
[here](./advanced_networking.md#nat-traversal-port-forwarding).

### What should I do if I lose my slashing protection database?

See [here](./slashing-protection.md#misplaced-slashing-database).

### How do I update lighthouse?

If you are updating to new release binaries, it will be the same process as described [here.](./installation-binaries.md)

If you are updating by rebuilding from source, see [here.](./installation-source.md#update-lighthouse)

If you are running the docker image provided by Sigma Prime on Dockerhub, you can update to specific versions, for example:

```bash
$ docker pull sigp/lighthouse:v1.0.0
```

If you are building a docker image, the process will be similar to the one described [here.](./docker.md#building-the-docker-image)
You will just also need to make sure the code you have checked out is up to date.

### I can't compile lighthouse

See [here.](./installation-source.md#troubleshooting)

### What is "Syncing deposit contract block cache"?

```
Nov 30 21:04:28.268 WARN Syncing deposit contract block cache   est_blocks_remaining: initializing deposits, service: slot_notifier
```

This log indicates that your beacon node is downloading blocks and deposits
from your execution node. When the `est_blocks_remaining` is
`initializing_deposits`, your node is downloading deposit logs. It may stay in
this stage for several minutes. Once the deposits logs are finished
downloading, the `est_blocks_remaining` value will start decreasing.

It is perfectly normal to see this log when starting a node for the first time
or after being off for more than several minutes.

If this log continues appearing sporadically during operation, there may be an
issue with your execution client endpoint.

### Can I use redundancy in my staking setup?

You should **never** use duplicate/redundant validator keypairs or validator clients (i.e., don't
duplicate your JSON keystores and don't run `lighthouse vc` twice). This will lead to slashing.

However, there are some components which can be configured with redundancy. See the
[Redundancy](./redundancy.md) guide for more information.

### How can I monitor my validators?

Apart from using block explorers, you may use the "Validator Monitor" built into Lighthouse which
provides logging and Prometheus/Grafana metrics for individual validators. See [Validator
Monitoring](./validator-monitoring.md) for more information. Lighthouse has also developed Lighthouse UI (Siren) to monitor performance, see [Lighthouse UI (Siren)](./lighthouse-ui.md).

### I see beacon logs showing `WARN: Execution engine called failed`, what should I do?

The `WARN Execution engine called failed` log is shown when the beacon node cannot reach the execution engine. When this warning occurs, it will be followed by a detailed message. A frequently encountered example of the error message is:

`error: Reqwest(reqwest::Error { kind: Request, url: Url { scheme: "http", cannot_be_a_base: false, username: "", password: None, host: Some(Ipv4(127.0.0.1)), port: Some(8551), path: "/", query: None, fragment: None }, source: TimedOut }), service: exec`

which says `TimedOut` at the end of the message. This means that the execution engine has not responded in time to the beacon node. There are a few reasons why this can occur:
1. The execution engine is not synced. Check the log of the execution engine to make sure that it is synced. If it is syncing, wait until it is synced and the error will disappear. You will see the beacon node logs `INFO Execution engine online` when it is synced. 
1. The computer is overloaded. Check the CPU and RAM usage to see if it has overloaded. You can use `htop` to check for CPU and RAM usage.
1. Your SSD is slow. Check if your SSD is in "The Bad" list [here](https://gist.github.com/yorickdowne/f3a3e79a573bf35767cd002cc977b038). If your SSD is in "The Bad" list, it means it cannot keep in sync to the network and you may want to consider upgrading to a better SSD.

If the reason for the error message is caused by no. 1 above, you may want to look further. If the execution engine is out of sync suddenly, it is usually caused by ungraceful shutdown. The common causes for ungraceful shutdown are:
- Power outage. If power outages are an issue at your place, consider getting a UPS to avoid ungraceful shutdown of services. 
- The service file is not stopped properly. To overcome this, make sure that the process is stop properly, e.g., during client updates. 
- Out of memory (oom) error. This can happen when the system memory usage has reached its maximum and causes the execution engine to be killed. When this occurs, the log file will show `Main process exited, code=killed, status=9/KILL`.  You can also run `sudo journalctl -a --since "18 hours ago" | grep -i "killed process` to confirm that the execution client has been killed due to oom. If you are using geth as the execution client, a short term solution is to reduce the resources used, for example: (1) reduce the cache by adding the flag `--cache 2048` (2) connect to less peers using the flag `--maxpeers 10`. If the oom occurs rather frequently, a long term solution is to increase the memory capacity of the computer.


### How do I check or update my withdrawal credentials? 
Withdrawals will be available after the Capella/Shanghai upgrades on 12<sup>th</sup> April 2023. To check that if you are eligible for withdrawals, go to [Staking launchpad](https://launchpad.ethereum.org/en/withdrawals), enter your validator index and click `verify on mainnet`:
- `withdrawals enabled` means you will automatically receive withdrawals to the withdrawal address that you set.
- `withdrawals not enabled` means you will need to update your withdrawal credentials from `0x00` type to `0x01` type. The common way to do this is using `Staking deposit CLI` or `ethdo`, with the instructions available [here](https://launchpad.ethereum.org/en/withdrawals#update-your-keys). 

For the case of `withdrawals not enabled`, you can update your withdrawal credentials **anytime**, and there is no deadline for that. The catch is that as long as you do not update your withdrawal credentials, your rewards in the beacon chain will continue to be locked in the beacon chain. Only after you update the withdrawal credentials, will the rewards be withdrawn to the withdrawal address.


### I am missing attestations. Why? 
The first thing is to ensure both consensus and execution clients are synced with the network. If they are synced, there may still be some issues with the node setup itself that is causing the missed attestations. Check the setup to ensure that:
- the clock is synced
- the computer has sufficient resources and is not overloaded
- the internet is working well
- you have sufficient peers

You can see more information on the [Ethstaker KB](https://ethstaker.gitbook.io/ethstaker-knowledge-base/help/missed-attestations). Once the above points are good, missing attestation should be a rare occurance. 

### Sometimes I miss the attestation head vote, resulting in penalty. Is this normal?

In general it is unavoiadable to have some penalties occasionally. This is particularly the case when you are assigned to attest on the first slot of an epoch and if the proposer of that slot releases the block late, then you will get penalised for missing the target and head votes. Your attestation performance does not only depend on your own setup, but also on everyone else's performance.


### My beacon node is stuck at downloading historical block using checkpoing sync. What can I do?

Check the number of peers you are connected to. If you have low peers (less than 50), try to do port forwarding on the port 9000 TCP/UDP to increase peer count.