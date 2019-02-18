use crate::{Address, Epoch, Hash256, Slot};
use bls::Signature;

const GWEI: u64 = 1_000_000_000;

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
    pub shuffle_round_count: u8,

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
    pub min_attestation_inclusion_delay: u64,
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

impl ChainSpec {
    /// Returns a `ChainSpec` compatible with the specification from Ethereum Foundation.
    ///
    /// Of course, the actual foundation specs are unknown at this point so these are just a rough
    /// estimate.
    ///
    /// Spec v0.2.0
    pub fn foundation() -> Self {
        let genesis_slot = Slot::new(2_u64.pow(19));
        let epoch_length = 64;
        let genesis_epoch = genesis_slot.epoch(epoch_length);

        Self {
            /*
             * Misc
             */
            shard_count: 1_024,
            target_committee_size: 128,
            max_balance_churn_quotient: 32,
            beacon_chain_shard_number: u64::max_value(),
            max_indices_per_slashable_vote: 4_096,
            max_withdrawals_per_epoch: 4,
            shuffle_round_count: 90,

            /*
             *  Deposit contract
             */
            deposit_contract_address: Address::zero(),
            deposit_contract_tree_depth: 32,

            /*
             *  Gwei values
             */
            min_deposit_amount: u64::pow(2, 0) * GWEI,
            max_deposit_amount: u64::pow(2, 5) * GWEI,
            fork_choice_balance_increment: u64::pow(2, 0) * GWEI,
            ejection_balance: u64::pow(2, 4) * GWEI,

            /*
             * Initial Values
             */
            genesis_fork_version: 0,
            genesis_slot: Slot::new(2_u64.pow(19)),
            genesis_epoch,
            genesis_start_shard: 0,
            far_future_epoch: Epoch::new(u64::max_value()),
            zero_hash: Hash256::zero(),
            empty_signature: Signature::empty_signature(),
            bls_withdrawal_prefix_byte: 0,

            /*
             * Time parameters
             */
            slot_duration: 6,
            min_attestation_inclusion_delay: 4,
            epoch_length,
            seed_lookahead: Epoch::new(1),
            entry_exit_delay: 4,
            eth1_data_voting_period: 16,
            min_validator_withdrawal_epochs: Epoch::new(256),

            /*
             * State list lengths
             */
            latest_block_roots_length: 8_192,
            latest_randao_mixes_length: 8_192,
            latest_index_roots_length: 8_192,
            latest_penalized_exit_length: 8_192,

            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 32,
            whistleblower_reward_quotient: 512,
            includer_reward_quotient: 8,
            inactivity_penalty_quotient: 16_777_216,

            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_attester_slashings: 1,
            max_attestations: 128,
            max_deposits: 16,
            max_exits: 16,

            /*
             * Signature domains
             */
            domain_deposit: 0,
            domain_attestation: 1,
            domain_proposal: 2,
            domain_exit: 3,
            domain_randao: 4,
        }
    }
}

impl ChainSpec {
    /// Returns a `ChainSpec` compatible with the specification suitable for 8 validators.
    ///
    /// Spec v0.2.0
    pub fn few_validators() -> Self {
        let genesis_slot = Slot::new(2_u64.pow(19));
        let epoch_length = 8;
        let genesis_epoch = genesis_slot.epoch(epoch_length);

        Self {
            shard_count: 1,
            target_committee_size: 1,
            genesis_slot,
            genesis_epoch,
            epoch_length,
            ..ChainSpec::foundation()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_foundation_spec_can_be_constructed() {
        let _ = ChainSpec::foundation();
    }
}
