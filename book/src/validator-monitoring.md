# Validator Monitoring

Lighthouse allows for fine-grained monitoring of specific validators using the "validator monitor".
Generally users will want to use this function to track their own validators, however, it can be
used for any validator, regardless of who controls it.

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
lighthouse bn --staking --validator-monitor-auto
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
dashboard contains all/most of the metrics exposed via the validator monitor.
