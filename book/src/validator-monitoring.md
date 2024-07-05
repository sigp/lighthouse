# Validator Monitoring

Lighthouse allows for fine-grained monitoring of specific validators using the "validator monitor".
Generally users will want to use this function to track their own validators, however, it can be
used for any validator, regardless of who controls it.

_Note: If you are looking for remote metric monitoring, please see the docs on
[Prometheus Metrics](./advanced_metrics.md)_.

## Monitoring is in the Beacon Node

Lighthouse performs validator monitoring in the Beacon Node (BN) instead of the Validator Client
(VC). This is contrary to what some users may expect, but it has several benefits:

1. It keeps the VC simple. The VC handles cryptographic signing and the developers believe it should
   be doing as little additional work as possible.
1. The BN has a better knowledge of the chain and network. Communicating all this information to
   the VC is impractical, we can provide more information when monitoring with the BN.
1. It is more flexible:
    - Users can use a local BN to observe some validators running in a remote location.
    - Users can monitor validators that are not their own.

## How to Enable Monitoring

The validator monitor is always enabled in Lighthouse, but it might not have any enrolled
validators. There are two methods for a validator to be enrolled for additional monitoring;
automatic and manual.

### Automatic

When the `--validator-monitor-auto` flag is supplied, any validator which uses the
[`beacon_committee_subscriptions`](https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet)
API endpoint will be enrolled for additional monitoring. All active validators will use this
endpoint each epoch, so you can expect it to detect all local and active validators within several
minutes after start up.

#### Example

```
lighthouse bn --http --validator-monitor-auto
```

### Manual

The `--validator-monitor-pubkeys` flag can be used to specify validator public keys for monitoring.
This is useful when monitoring validators that are not directly attached to this BN.

> Note: when monitoring validators that aren't connected to this BN, supply the
> `--subscribe-all-subnets --import-all-attestations` flags to ensure the BN has a full view of the
> network. This is not strictly necessary, though.

#### Example

Monitor the mainnet validators at indices `0` and `1`:

```
lighthouse bn --validator-monitor-pubkeys 0x933ad9491b62059dd065b560d256d8957a8c402cc6e8d8ee7290ae11e8f7329267a8811c397529dac52ae1342ba58c95,0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c
```

> Note: The validator monitoring will stop collecting per-validator Prometheus metrics and issuing per-validator logs when the number of validators reaches 64. To continue collecting metrics and logging, use the flag `--validator-monitor-individual-tracking-threshold N` where `N` is a number greater than the number of validators to monitor.

## Observing Monitoring

Enrolling a validator for additional monitoring results in:

- Additional logs to be printed during BN operation.
- Additional [Prometheus metrics](./advanced_metrics.md) from the BN.

### Logging

Lighthouse will create logs for the following events for each monitored validator:

- A block from the validator is observed.
- An unaggregated attestation from the validator is observed.
- An unaggregated attestation from the validator is included in an aggregate.
- An unaggregated attestation from the validator is included in a block.
- An aggregated attestation from the validator is observed.
- An exit for the validator is observed.
- A slashing (proposer or attester) is observed which implicates that validator.

#### Example

```
Jan 18 11:50:03.896 INFO Unaggregated attestation                validator: 0, src: gossip, slot: 342248, epoch: 10695, delay_ms: 891, index: 12, head: 0x5f9d603c04b5489bf2de3708569226fd9428eb40a89c75945e344d06c7f4f86a, service: beacon
```

```
Jan 18 11:32:55.196 INFO Attestation included in aggregate       validator: 0, src: gossip, slot: 342162, epoch: 10692, delay_ms: 2193, index: 10, head: 0x9be04ecd04bf82952dad5d12c62e532fd13a8d42afb2e6ee98edaf05fc7f9f30, service: beacon
```

```
Jan 18 11:21:09.808 INFO Attestation included in block           validator: 1, slot: 342102, epoch: 10690, inclusion_lag: 0 slot(s), index: 7, head: 0x422bcd14839e389f797fd38b01e31995f91bcaea3d5d56457fc6aac76909ebac, service: beacon
```

### Metrics

The
[`ValidatorMonitor`](https://github.com/sigp/lighthouse-metrics/blob/master/dashboards/ValidatorMonitor.json)
dashboard contains most of the metrics exposed via the validator monitor.

### Attestation Simulator Metrics

Lighthouse v4.6.0 introduces a new feature to track the performance of a beacon node. This feature internally simulates an attestation for each slot, and outputs a hit or miss for the head, target and source votes. The attestation simulator is turned on automatically (even when there are no validators) and prints logs in the debug level.

> Note: The simulated attestations are never published to the network, so the simulator does not reflect the attestation performance of a validator.

The attestation simulation prints the following logs when simulating an attestation:

```
DEBG Simulating unagg. attestation production, service: beacon, module: beacon_chain::attestation_simulator:39
DEBG Produce unagg. attestation, attestation_target: 0x59fc…1a67, attestation_source: 0xc4c5…d414, service: beacon, module: beacon_chain::attestation_simulator:87
```

When the simulated attestation has completed, it prints a log that specifies if the head, target and source votes are hit.  An example of a log when all head, target and source are hit:

```
DEBG Simulated attestation evaluated, head_hit: true, target_hit: true, source_hit: true, attestation_slot: Slot(1132616), attestation_head: 0x61367335c30b0f114582fe298724b75b56ae9372bdc6e7ce5d735db68efbdd5f, attestation_target: 0xaab25a6d01748cf4528e952666558317b35874074632550c37d935ca2ec63c23, attestation_source: 0x13ccbf8978896c43027013972427ee7ce02b2bb9b898dbb264b870df9288c1e7, service: val_mon, service: beacon, module: beacon_chain::validator_monitor:2051
```

An example of a log when the head is missed:

```
DEBG Simulated attestation evaluated, head_hit: false, target_hit: true, source_hit: true, attestation_slot: Slot(1132623), attestation_head: 0x1c0e53c6ace8d0ff57f4a963e4460fe1c030b37bf1c76f19e40928dc2e214c59, attestation_target: 0xaab25a6d01748cf4528e952666558317b35874074632550c37d935ca2ec63c23, attestation_source: 0x13ccbf8978896c43027013972427ee7ce02b2bb9b898dbb264b870df9288c1e7, service: val_mon, service: beacon, module: beacon_chain::validator_monitor:2051
```

With `--metrics` enabled on the beacon node, the following metrics will be recorded:

```
validator_monitor_attestation_simulator_head_attester_hit_total
validator_monitor_attestation_simulator_head_attester_miss_total
validator_monitor_attestation_simulator_target_attester_hit_total
validator_monitor_attestation_simulator_target_attester_miss_total
validator_monitor_attestation_simulator_source_attester_hit_total
validator_monitor_attestation_simulator_source_attester_miss_total
```

A grafana dashboard to view the metrics for attestation simulator is available [here](https://github.com/sigp/lighthouse-metrics/blob/master/dashboards/AttestationSimulator.json).

The attestation simulator provides an insight into the attestation performance of a beacon node. It can be used as an indication of how expediently the beacon node has completed importing blocks within the 4s time frame for an attestation to be made.

The attestation simulator _does not_ consider:

- the latency between the beacon node and the validator client
- the potential delays when publishing the attestation to the network

which are critical factors to consider when evaluating the attestation performance of a validator.

Assuming the above factors are ignored (no delays between beacon node and validator client, and in publishing the attestation to the network):

1. If the attestation simulator says that all votes are hit, it means that if the beacon node were to publish the attestation for this slot, the validator should receive the rewards for the head, target and source votes.

1. If the attestation simulator says that the one or more votes are missed, it means that there is a delay in importing the block. The delay could be due to slowness in processing the block (e.g., due to a slow CPU) or that the block is arriving late (e.g., the proposer publishes the block late). If the beacon node were to publish the attestation for this slot, the validator will miss one or more votes (e.g., the head vote).
