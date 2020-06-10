# Lighthouse REST API: `/spec`

The `/spec` endpoints provide information about Eth2.0 specifications that the node is running.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/spec`](#spec) | Get the full spec object that a node's running.
[`/spec/slots_per_epoch`](#specslots_per_epoch) | Get the number of slots per epoch.
[`/spec/eth2_config`](#specseth2_config) | Get the full Eth2 config object.

## `/spec`

Requests the full spec object that a node's running.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/spec`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "genesis_slot": 0,
    "base_rewards_per_epoch": 4,
    "deposit_contract_tree_depth": 32,
    "max_committees_per_slot": 64,
    "target_committee_size": 128,
    "min_per_epoch_churn_limit": 4,
    "churn_limit_quotient": 65536,
    "shuffle_round_count": 90,
    "min_genesis_active_validator_count": 16384,
    "min_genesis_time": 1578009600,
    "min_deposit_amount": 1000000000,
    "max_effective_balance": 32000000000,
    "ejection_balance": 16000000000,
    "effective_balance_increment": 1000000000,
    "genesis_fork_version": "0x00000000",
    "bls_withdrawal_prefix_byte": "0x00",
    "genesis_delay": 172800,
    "milliseconds_per_slot": 12000,
    "min_attestation_inclusion_delay": 1,
    "min_seed_lookahead": 1,
    "max_seed_lookahead": 4,
    "min_epochs_to_inactivity_penalty": 4,
    "min_validator_withdrawability_delay": 256,
    "shard_committee_period": 2048,
    "base_reward_factor": 64,
    "whistleblower_reward_quotient": 512,
    "proposer_reward_quotient": 8,
    "inactivity_penalty_quotient": 33554432,
    "min_slashing_penalty_quotient": 32,
    "domain_beacon_proposer": 0,
    "domain_beacon_attester": 1,
    "domain_randao": 2,
    "domain_deposit": 3,
    "domain_voluntary_exit": 4,
    "safe_slots_to_update_justified": 8,
    "eth1_follow_distance": 1024,
    "seconds_per_eth1_block": 14,
    "boot_nodes": [],
    "network_id": 1
}
```

## `/spec/eth2_config`

Requests the full `Eth2Config` object.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/spec/eth2_config`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "spec_constants": "mainnet",
    "spec": {
        "genesis_slot": 0,
        "base_rewards_per_epoch": 4,
        "deposit_contract_tree_depth": 32,
        "max_committees_per_slot": 64,
        "target_committee_size": 128,
        "min_per_epoch_churn_limit": 4,
        "churn_limit_quotient": 65536,
        "shuffle_round_count": 90,
        "min_genesis_active_validator_count": 16384,
        "min_genesis_time": 1578009600,
        "min_deposit_amount": 1000000000,
        "max_effective_balance": 32000000000,
        "ejection_balance": 16000000000,
        "effective_balance_increment": 1000000000,
        "genesis_fork_version": "0x00000000",
        "bls_withdrawal_prefix_byte": "0x00",
        "genesis_delay": 172800,
        "milliseconds_per_slot": 12000,
        "min_attestation_inclusion_delay": 1,
        "min_seed_lookahead": 1,
        "max_seed_lookahead": 4,
        "min_epochs_to_inactivity_penalty": 4,
        "min_validator_withdrawability_delay": 256,
        "shard_committee_period": 2048,
        "base_reward_factor": 64,
        "whistleblower_reward_quotient": 512,
        "proposer_reward_quotient": 8,
        "inactivity_penalty_quotient": 33554432,
        "min_slashing_penalty_quotient": 32,
        "domain_beacon_proposer": 0,
        "domain_beacon_attester": 1,
        "domain_randao": 2,
        "domain_deposit": 3,
        "domain_voluntary_exit": 4,
        "safe_slots_to_update_justified": 8,
        "eth1_follow_distance": 1024,
        "seconds_per_eth1_block": 14,
        "boot_nodes": [],
        "network_id": 1
    }
}
```

## `/spec/slots_per_epoch`

Requests the `SLOTS_PER_EPOCH` parameter from the specs that the node is running.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/spec/slots_per_epoch`
Method | GET
JSON Encoding | Number
Query Parameters | None
Typical Responses | 200

### Example Response

```json
32
```