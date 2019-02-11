mod foundation;

use crate::{Address, Epoch, Hash256, Slot};
use bls::Signature;

/// Holds all the "constants" for a BeaconChain.
///
/// Spec v0.2.0
#[derive(PartialEq, Debug, Clone)]
pub struct ChainSpec {
    /*
     * Misc
     */
    pub shard_count: u64,
    pub target_committee_size: u64,
    pub max_balance_churn_quotient: u64,
    pub beacon_chain_shard_number: u64,
    pub max_indices_per_slashable_vote: u64,
    pub max_withdrawals_per_epoch: u64,
    pub shuffle_round_count: u64,

    /*
     *  Deposit contract
     */
    pub deposit_contract_address: Address,
    pub deposit_contract_tree_depth: u64,

    /*
     *  Gwei values
     */
    pub min_deposit_amount: u64,
    pub max_deposit_amount: u64,
    pub fork_choice_balance_increment: u64,
    pub ejection_balance: u64,

    /*
     * Initial Values
     */
    pub genesis_fork_version: u64,
    pub genesis_slot: Slot,
    pub genesis_epoch: Epoch,
    pub genesis_start_shard: u64,
    pub far_future_epoch: Epoch,
    pub zero_hash: Hash256,
    pub empty_signature: Signature,
    pub bls_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub slot_duration: u64,
    pub min_attestation_inclusion_delay: Slot,
    pub epoch_length: u64,
    pub seed_lookahead: Epoch,
    pub entry_exit_delay: u64,
    pub eth1_data_voting_period: u64,
    pub min_validator_withdrawal_epochs: Epoch,

    /*
     * State list lengths
     */
    pub latest_block_roots_length: usize,
    pub latest_randao_mixes_length: usize,
    pub latest_index_roots_length: usize,
    pub latest_penalized_exit_length: usize,

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
    pub max_attester_slashings: u64,
    pub max_attestations: u64,
    pub max_deposits: u64,
    pub max_exits: u64,

    /*
     * Signature domains
     */
    pub domain_deposit: u64,
    pub domain_attestation: u64,
    pub domain_proposal: u64,
    pub domain_exit: u64,
    pub domain_randao: u64,
}
