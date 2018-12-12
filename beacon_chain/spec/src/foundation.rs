use super::ChainSpec;

use types::{Address, Hash256};

impl ChainSpec {
    /// Returns a `ChainSpec` compatible with the specification from Ethereum Foundation.
    pub fn foundation() -> Self {
        Self {
            /*
             * Misc
             */
            shard_count: 1_024,
            target_committee_size: 256,
            ejection_balance: 16,
            max_balance_churn_quotient: 32,
            gwei_per_eth: u64::pow(10, 9),
            beacon_chain_shard_number: u64::max_value(),
            bls_withdrawal_prefix_byte: 0x00,
            max_casper_votes: 1_024,
            /*
             *  Deposit contract
             */
            deposit_contract_address: Address::from("TBD".as_bytes()),
            deposit_contract_tree_depth: 32,
            min_deposit: 1,
            max_deposit: 32,
            /*
             * Initial Values
             */
            initial_fork_version: 0,
            initial_slot_number: 0,
            zero_hash: Hash256::zero(),
            /*
             * Time parameters
             */
            slot_duration: 6,
            min_attestation_inclusion_delay: 4,
            epoch_length: 64,
            min_validator_registry_change_interval: 256,
            pow_receipt_root_voting_period: 1_024,
            shard_persistent_committee_change_period: u64::pow(2, 17),
            collective_penalty_calculation_period: u64::pow(2, 20),
            zero_balance_validator_ttl: u64::pow(2, 22),
            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 2_048,
            whistleblower_reward_quotient: 512,
            includer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::pow(2, 34),
            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_casper_slashings: 15,
            max_attestations: 128,
            max_deposits: 16,
            max_exits: 16,
        }
    }
}
