mod foundation;

use crate::{Address, Eth1Data, Hash256, Validator};
use bls::Signature;

#[derive(PartialEq, Debug)]
pub struct ChainSpec {
    /*
     * Misc
     */
    pub shard_count: u64,
    pub target_committee_size: u64,
    pub ejection_balance: u64,
    pub max_balance_churn_quotient: u64,
    pub beacon_chain_shard_number: u64,
    pub max_casper_votes: u64,
    pub latest_block_roots_length: u64,
    pub latest_randao_mixes_length: u64,
    pub latest_penalized_exit_length: u64,
    pub max_withdrawals_per_epoch: u64,
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
    pub genesis_fork_version: u64,
    pub genesis_slot: u64,
    pub genesis_start_shard: u64,
    pub far_future_slot: u64,
    pub zero_hash: Hash256,
    pub empty_signature: Signature,
    pub bls_withdrawal_prefix_byte: u8,
    /*
     * Time parameters
     */
    pub slot_duration: u64,
    pub min_attestation_inclusion_delay: u64,
    pub epoch_length: u64,
    pub seed_lookahead: u64,
    pub entry_exit_delay: u64,
    pub eth1_data_voting_period: u64,
    pub min_validator_withdrawal_time: u64,
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
    /*
     * Intialization parameters
     */
    pub initial_validators: Vec<Validator>,
    pub initial_balances: Vec<u64>,
    pub genesis_time: u64,
    pub intial_eth1_data: Eth1Data,
}
