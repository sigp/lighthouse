use serde_derive::{Deserialize, Serialize};
use std::io::Read;
use types::ChainSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlConfig {
    // Misc
    shard_count: u64,
    target_committee_size: u64,
    max_validators_per_committee: u64,
    min_per_epoch_churn_limit: u64,
    churn_limit_quotient: u64,
    shuffle_round_count: u64,
    min_genesis_active_validator_count: u64,
    min_genesis_time: u64,
    deposit_contract_address: String,

    // Gwei values
    min_deposit_amount: u64,
    max_effective_balance: u64,
    ejection_balance: u64,
    effective_balance_increment: u64,

    // Initial values
    genesis_slot: u64,
    bls_withdrawal_prefix: u64,

    // Time parameters
    seconds_per_slot: u64,
    min_attestation_inclusion_delay: u64,
    slots_per_epoch: u64,
    min_seed_lookahead: u64,
    activation_exit_delay: u64,
    slots_per_eth1_voting_period: u64,
    slots_per_historical_root: u64,
    min_validator_withdrawability_delay: u64,
    persistent_committee_period: u64,
    max_epochs_per_crosslink: u64,
    min_epochs_to_inactivity_penalty: u64,
    early_derived_secret_penalty_max_future_epochs: u64,

    // State vector lengths
    epochs_per_historical_vector: u64,
    epochs_per_slashings_vector: u64,
    historical_roots_limit: u64,
    validator_registry_limit: u64,

    // Reward and penalty quotients
    base_reward_factor: u64,
    whistleblower_reward_quotient: u64,
    proposer_reward_quotient: u64,
    inactivity_penalty_quotient: u64,
    min_slashing_penalty_quotient: u64,

    // Max operations per block
    max_proposer_slashings: u64,
    max_attester_slashings: u64,
    max_attestations: u64,
    max_deposits: u64,
    max_voluntary_exits: u64,
    max_transfers: u64,

    // Signature domains
    domain_beacon_proposer: String,
    domain_randao: String,
    domain_attestation: String,
    domain_deposit: String,
    domain_voluntary_exit: String,
    domain_transfer: String,
    domain_custody_bit_challenge: String,
    domain_shard_proposer: String,
    domain_shard_attester: String,
}

pub fn apply_yaml_config_to_spec(reader: impl Read, spec: &mut ChainSpec) -> Result<(), String> {
    let config = serde_yaml::from_reader(reader)
        .map_err(|e| format!("Failed to deserialize YAML config: {:?}", e))?;
    Ok(())
}
