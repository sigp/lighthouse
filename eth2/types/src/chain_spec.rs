use crate::*;
use int_to_bytes::int_to_bytes4;
use serde_derive::Deserialize;
use test_utils::u8_from_hex_str;

/// Each of the BLS signature domains.
///
/// Spec v0.6.1
pub enum Domain {
    BeaconProposer,
    Randao,
    Attestation,
    Deposit,
    VoluntaryExit,
    Transfer,
}

/// Holds all the "constants" for a BeaconChain.
///
/// Spec v0.6.1
#[derive(PartialEq, Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ChainSpec {
    /*
     * Misc
     */
    pub shard_count: u64,
    pub target_committee_size: u64,
    pub max_indices_per_attestation: u64,
    pub min_per_epoch_churn_limit: u64,
    pub churn_limit_quotient: u64,
    pub base_rewards_per_epoch: u64,
    pub shuffle_round_count: u8,

    /*
     *  Deposit contract
     */
    pub deposit_contract_tree_depth: u64,

    /*
     *  Gwei values
     */
    pub min_deposit_amount: u64,
    pub max_effective_balance: u64,
    pub ejection_balance: u64,
    pub effective_balance_increment: u64,

    /*
     * Initial Values
     */
    pub genesis_slot: Slot,
    pub genesis_epoch: Epoch,
    pub far_future_epoch: Epoch,
    pub zero_hash: Hash256,
    #[serde(deserialize_with = "u8_from_hex_str")]
    pub bls_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub seconds_per_slot: u64,
    pub min_attestation_inclusion_delay: u64,
    pub slots_per_epoch: u64,
    pub min_seed_lookahead: Epoch,
    pub activation_exit_delay: u64,
    pub slots_per_eth1_voting_period: u64,
    pub slots_per_historical_root: usize,
    pub min_validator_withdrawability_delay: Epoch,
    pub persistent_committee_period: u64,
    pub max_crosslink_epochs: u64,
    pub min_epochs_to_inactivity_penalty: u64,

    /*
     * State list lengths
     */
    pub latest_randao_mixes_length: usize,
    pub latest_active_index_roots_length: usize,
    pub latest_slashed_exit_length: usize,

    /*
     * Reward and penalty quotients
     */
    pub base_reward_quotient: u64,
    pub whistleblowing_reward_quotient: u64,
    pub proposer_reward_quotient: u64,
    pub inactivity_penalty_quotient: u64,
    pub min_slashing_penalty_quotient: u64,

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
    domain_beacon_proposer: u32,
    domain_randao: u32,
    domain_attestation: u32,
    domain_deposit: u32,
    domain_voluntary_exit: u32,
    domain_transfer: u32,

    /*
     * Network specific parameters
     *
     */
    pub boot_nodes: Vec<Multiaddr>,
    pub chain_id: u8,
}

impl ChainSpec {
    /// Return the number of committees in one epoch.
    ///
    /// Spec v0.6.1
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
    /// Spec v0.6.1
    pub fn get_domain(&self, epoch: Epoch, domain: Domain, fork: &Fork) -> u64 {
        let domain_constant = match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::Randao => self.domain_randao,
            Domain::Attestation => self.domain_attestation,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
            Domain::Transfer => self.domain_transfer,
        };

        let mut bytes: Vec<u8> = fork.get_fork_version(epoch).to_vec();
        bytes.append(&mut int_to_bytes4(domain_constant));

        let mut fork_and_domain = [0; 8];
        fork_and_domain.copy_from_slice(&bytes);

        u64::from_le_bytes(fork_and_domain)
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    ///
    /// Spec v0.6.1
    pub fn foundation() -> Self {
        Self {
            /*
             * Misc
             */
            shard_count: 1_024,
            target_committee_size: 128,
            max_indices_per_attestation: 4096,
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            base_rewards_per_epoch: 5,
            shuffle_round_count: 90,

            /*
             *  Deposit contract
             */
            deposit_contract_tree_depth: 32,

            /*
             *  Gwei values
             */
            min_deposit_amount: u64::pow(2, 0) * u64::pow(10, 9),
            max_effective_balance: u64::pow(2, 5) * u64::pow(10, 9),
            ejection_balance: u64::pow(2, 4) * u64::pow(10, 9),
            effective_balance_increment: u64::pow(2, 0) * u64::pow(10, 9),

            /*
             * Initial Values
             */
            genesis_slot: Slot::new(0),
            genesis_epoch: Epoch::new(0),
            far_future_epoch: Epoch::new(u64::max_value()),
            zero_hash: Hash256::zero(),
            bls_withdrawal_prefix_byte: 0,

            /*
             * Time parameters
             */
            seconds_per_slot: 6,
            min_attestation_inclusion_delay: 4,
            slots_per_epoch: 64,
            min_seed_lookahead: Epoch::new(1),
            activation_exit_delay: 4,
            slots_per_eth1_voting_period: 1_024,
            slots_per_historical_root: 8_192,
            min_validator_withdrawability_delay: Epoch::new(256),
            persistent_committee_period: 2_048,
            max_crosslink_epochs: 64,
            min_epochs_to_inactivity_penalty: 4,

            /*
             * State list lengths
             */
            latest_randao_mixes_length: 8_192,
            latest_active_index_roots_length: 8_192,
            latest_slashed_exit_length: 8_192,

            /*
             * Reward and penalty quotients
             */
            base_reward_quotient: 32,
            whistleblowing_reward_quotient: 512,
            proposer_reward_quotient: 8,
            inactivity_penalty_quotient: 33_554_432,
            min_slashing_penalty_quotient: 32,

            /*
             * Max operations per block
             */
            max_proposer_slashings: 16,
            max_attester_slashings: 1,
            max_attestations: 128,
            max_deposits: 16,
            max_voluntary_exits: 16,
            max_transfers: 0,

            /*
             * Signature domains
             */
            domain_beacon_proposer: 0,
            domain_randao: 1,
            domain_attestation: 2,
            domain_deposit: 3,
            domain_voluntary_exit: 4,
            domain_transfer: 5,

            /*
             * Boot nodes
             */
            boot_nodes: vec![],
            chain_id: 1, // foundation chain id
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
            chain_id: 2, // lighthouse testnet chain id
            ..ChainSpec::few_validators()
        }
    }

    /// Returns a `ChainSpec` compatible with the specification suitable for 8 validators.
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

impl Default for ChainSpec {
    fn default() -> Self {
        Self::foundation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use int_to_bytes::int_to_bytes8;

    #[test]
    fn test_foundation_spec_can_be_constructed() {
        let _ = ChainSpec::foundation();
    }

    fn test_domain(domain_type: Domain, raw_domain: u32, spec: &ChainSpec) {
        let fork = Fork::genesis(&spec);
        let epoch = Epoch::new(0);

        let domain = spec.get_domain(epoch, domain_type, &fork);

        let mut expected = fork.get_fork_version(epoch).to_vec();
        expected.append(&mut int_to_bytes4(raw_domain));

        assert_eq!(int_to_bytes8(domain), expected);
    }

    #[test]
    fn test_get_domain() {
        let spec = ChainSpec::foundation();

        test_domain(Domain::BeaconProposer, spec.domain_beacon_proposer, &spec);
        test_domain(Domain::Randao, spec.domain_randao, &spec);
        test_domain(Domain::Attestation, spec.domain_attestation, &spec);
        test_domain(Domain::Deposit, spec.domain_deposit, &spec);
        test_domain(Domain::VoluntaryExit, spec.domain_voluntary_exit, &spec);
        test_domain(Domain::Transfer, spec.domain_transfer, &spec);
    }
}
