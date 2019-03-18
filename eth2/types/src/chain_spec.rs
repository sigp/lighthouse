use crate::{Address, Epoch, Fork, Hash256, Multiaddr, Slot};
use bls::Signature;

const GWEI: u64 = 1_000_000_000;

pub enum Domain {
    Deposit,
    Attestation,
    Proposal,
    Exit,
    Randao,
    Transfer,
}

/// Holds all the "constants" for a BeaconChain.
///
/// Spec v0.4.0
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
    pub max_exit_dequeues_per_epoch: u64,
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
    pub seconds_per_slot: u64,
    pub min_attestation_inclusion_delay: u64,
    pub slots_per_epoch: u64,
    pub min_seed_lookahead: Epoch,
    pub activation_exit_delay: u64,
    pub epochs_per_eth1_voting_period: u64,
    pub min_validator_withdrawability_delay: Epoch,

    /*
     * State list lengths
     */
    pub latest_block_roots_length: usize,
    pub latest_randao_mixes_length: usize,
    pub latest_active_index_roots_length: usize,
    pub latest_slashed_exit_length: usize,

    /*
     * Reward and penalty quotients
     */
    pub base_reward_quotient: u64,
    pub whistleblower_reward_quotient: u64,
    pub attestation_inclusion_reward_quotient: u64,
    pub inactivity_penalty_quotient: u64,
    pub min_penalty_quotient: u64,

    /*
     * Max operations per block
     */
    pub max_proposer_slashings: u64,
    pub max_attester_slashings: u64,
    pub max_attestations: u64,
    pub max_deposits: u64,
    pub max_voluntary_exits: u64,
    pub max_transfers: u64,

    /*
     * Signature domains
     *
     * Fields should be private to prevent accessing a domain that hasn't been modified to suit
     * some `Fork`.
     *
     * Use `ChainSpec::get_domain(..)` to access these values.
     */
    domain_deposit: u64,
    domain_attestation: u64,
    domain_proposal: u64,
    domain_exit: u64,
    domain_randao: u64,
    domain_transfer: u64,

    /*
     * Network specific parameters
     *
     */
    pub boot_nodes: Vec<Multiaddr>,
}

impl ChainSpec {
    /// Return the number of committees in one epoch.
    ///
    /// Spec v0.4.0
    pub fn get_epoch_committee_count(&self, active_validator_count: usize) -> u64 {
        std::cmp::max(
            1,
            std::cmp::min(
                self.shard_count / self.slots_per_epoch,
                active_validator_count as u64 / self.slots_per_epoch / self.target_committee_size,
            ),
        ) * self.slots_per_epoch
    }

    /// Get the domain number that represents the fork meta and signature domain.
    ///
    /// Spec v0.4.0
    pub fn get_domain(&self, epoch: Epoch, domain: Domain, fork: &Fork) -> u64 {
        let domain_constant = match domain {
            Domain::Deposit => self.domain_deposit,
            Domain::Attestation => self.domain_attestation,
            Domain::Proposal => self.domain_proposal,
            Domain::Exit => self.domain_exit,
            Domain::Randao => self.domain_randao,
            Domain::Transfer => self.domain_transfer,
        };

        let fork_version = fork.get_fork_version(epoch);
        fork_version * u64::pow(2, 32) + domain_constant
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    ///
    /// Spec v0.4.0
    pub fn foundation() -> Self {
        let genesis_slot = Slot::new(2_u64.pow(32));
        let slots_per_epoch = 64;
        let genesis_epoch = genesis_slot.epoch(slots_per_epoch);

        Self {
            /*
             * Misc
             */
            shard_count: 1_024,
            target_committee_size: 128,
            max_balance_churn_quotient: 32,
            beacon_chain_shard_number: u64::max_value(),
            max_indices_per_slashable_vote: 4_096,
            max_exit_dequeues_per_epoch: 4,
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
            genesis_slot,
            genesis_epoch,
            genesis_start_shard: 0,
            far_future_epoch: Epoch::new(u64::max_value()),
            zero_hash: Hash256::zero(),
            empty_signature: Signature::empty_signature(),
            bls_withdrawal_prefix_byte: 0,

            /*
             * Time parameters
             */
            seconds_per_slot: 6,
            min_attestation_inclusion_delay: 4,
            slots_per_epoch,
            min_seed_lookahead: Epoch::new(1),
            activation_exit_delay: 4,
            epochs_per_eth1_voting_period: 16,
            min_validator_withdrawability_delay: Epoch::new(256),

            /*
             * State list lengths
             */
            latest_block_roots_length: 8_192,
            latest_randao_mixes_length: 8_192,
            latest_active_index_roots_length: 8_192,
            latest_slashed_exit_length: 8_192,

            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 32,
            whistleblower_reward_quotient: 512,
            attestation_inclusion_reward_quotient: 8,
            inactivity_penalty_quotient: 16_777_216,
            min_penalty_quotient: 32,

            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_attester_slashings: 1,
            max_attestations: 128,
            max_deposits: 16,
            max_voluntary_exits: 16,
            max_transfers: 16,

            /*
             * Signature domains
             */
            domain_deposit: 0,
            domain_attestation: 1,
            domain_proposal: 2,
            domain_exit: 3,
            domain_randao: 4,
            domain_transfer: 5,

            /*
             * Boot nodes
             */
            boot_nodes: vec![],
        }
    }

    /// Returns a `ChainSpec` compatible with the Lighthouse testnet specification.
    ///
    /// Spec v0.4.0
    pub fn lighthouse_testnet() -> Self {
        /*
         * Lighthouse testnet bootnodes
         */
        let boot_nodes = vec!["/ip4/127.0.0.1/tcp/9000"
            .parse()
            .expect("correct multiaddr")];

        Self {
            boot_nodes,
            ..ChainSpec::few_validators()
        }
    }

    /// Returns a `ChainSpec` compatible with the specification suitable for 8 validators.
    ///
    /// Spec v0.4.0
    pub fn few_validators() -> Self {
        let genesis_slot = Slot::new(2_u64.pow(32));
        let slots_per_epoch = 8;
        let genesis_epoch = genesis_slot.epoch(slots_per_epoch);

        Self {
            shard_count: 8,
            target_committee_size: 1,
            genesis_slot,
            genesis_epoch,
            slots_per_epoch,
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
