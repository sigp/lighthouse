extern crate types;

mod foundation;

use types::{Address, Hash256};

#[derive(PartialEq, Debug)]
pub struct ChainSpec {
    /*
     * Misc
     */
    pub shard_count: u64,
    pub target_committee_size: u64,
    pub ejection_balance: u64,
    pub max_balance_churn_quotient: u64,
    pub gwei_per_eth: u64,
    pub beacon_chain_shard_number: u64,
    pub bls_withdrawal_prefix_byte: u8,
    pub max_casper_votes: u64,
    /*
     *  Deposit contract
     */
    pub deposit_contract_address: Address,
    pub deposit_contract_tree_depth: u64,
    pub min_deposit: u64,
    pub max_deposit: u64,
    /*
     * Initial Values
     */
    pub initial_fork_version: u64,
    pub initial_slot_number: u64,
    pub zero_hash: Hash256,
    /*
     * Time parameters
     */
    pub slot_duration: u64,
    pub min_attestation_inclusion_delay: u64,
    pub epoch_length: u64,
    pub min_validator_registry_change_interval: u64,
    pub pow_receipt_root_voting_period: u64,
    pub shard_persistent_committee_change_period: u64,
    pub collective_penalty_calculation_period: u64,
    pub zero_balance_validator_ttl: u64,
    /*
     * Reward and penalty quotients
     */
    pub base_reward_quotient: u64,
    pub whistleblower_reward_quotient: u64,
    pub includer_reward_quotient: u64,
    pub inactivity_penalty_quotient: u64,
    /*
     * Max operations per block
     */
    pub max_proposer_slashings: u64,
    pub max_casper_slashings: u64,
    pub max_attestations: u64,
    pub max_deposits: u64,
    pub max_exits: u64,
}
