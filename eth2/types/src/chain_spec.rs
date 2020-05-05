use crate::*;
use int_to_bytes::int_to_bytes4;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use tree_hash::TreeHash;
use utils::{
    fork_from_hex_str, fork_to_hex_str, u32_from_hex_str, u32_to_hex_str, u8_from_hex_str,
    u8_to_hex_str,
};

/// Each of the BLS signature domains.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Domain {
    BeaconProposer,
    BeaconAttester,
    Randao,
    Deposit,
    VoluntaryExit,
    SelectionProof,
    AggregateAndProof,
}

/// Holds all the "constants" for a BeaconChain.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChainSpec {
    /*
     * Constants
     */
    pub genesis_slot: Slot,
    #[serde(skip_serializing)] // skipped because Serde TOML has trouble with u64::max
    pub far_future_epoch: Epoch,
    pub base_rewards_per_epoch: u64,
    pub deposit_contract_tree_depth: u64,

    /*
     * Misc
     */
    pub max_committees_per_slot: usize,
    pub target_committee_size: usize,
    pub min_per_epoch_churn_limit: u64,
    pub churn_limit_quotient: u64,
    pub shuffle_round_count: u8,
    pub min_genesis_active_validator_count: u64,
    pub min_genesis_time: u64,
    pub hysteresis_quotient: u64,
    pub hysteresis_downward_multiplier: u64,
    pub hysteresis_upward_multiplier: u64,

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
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub genesis_fork_version: [u8; 4],
    #[serde(deserialize_with = "u8_from_hex_str", serialize_with = "u8_to_hex_str")]
    pub bls_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub min_genesis_delay: u64,
    pub milliseconds_per_slot: u64,
    pub min_attestation_inclusion_delay: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_epochs_to_inactivity_penalty: u64,
    pub min_validator_withdrawability_delay: Epoch,
    pub persistent_committee_period: u64,

    /*
     * Reward and penalty quotients
     */
    pub base_reward_factor: u64,
    pub whistleblower_reward_quotient: u64,
    pub proposer_reward_quotient: u64,
    pub inactivity_penalty_quotient: u64,
    pub min_slashing_penalty_quotient: u64,

    /*
     * Signature domains
     */
    domain_beacon_proposer: u32,
    domain_beacon_attester: u32,
    domain_randao: u32,
    domain_deposit: u32,
    domain_voluntary_exit: u32,
    domain_selection_proof: u32,
    domain_aggregate_and_proof: u32,

    /*
     * Fork choice
     */
    pub safe_slots_to_update_justified: u64,

    /*
     * Eth1
     */
    pub eth1_follow_distance: u64,
    pub seconds_per_eth1_block: u64,

    /*
     * Networking
     */
    pub boot_nodes: Vec<String>,
    pub network_id: u8,
    pub attestation_propagation_slot_range: u64,
    pub maximum_gossip_clock_disparity_millis: u64,
    pub target_aggregators_per_committee: u64,
    pub attestation_subnet_count: u64,
    pub random_subnets_per_validator: u64,
    pub epochs_per_random_subnet_subscription: u64,
}

impl ChainSpec {
    /// Returns an `EnrForkId` for the given `slot`.
    ///
    /// Presently, we don't have any forks so we just ignore the slot. In the future this function
    /// may return something different based upon the slot.
    pub fn enr_fork_id(&self, _slot: Slot, genesis_validators_root: Hash256) -> EnrForkId {
        EnrForkId {
            fork_digest: Self::compute_fork_digest(
                self.genesis_fork_version,
                genesis_validators_root,
            ),
            next_fork_version: self.genesis_fork_version,
            next_fork_epoch: self.far_future_epoch,
        }
    }

    /// Returns the epoch of the next scheduled change in the `fork.current_version`.
    ///
    /// There are no future forks scheduled so this function always returns `None`. This may not
    /// always be the case in the future, though.
    pub fn next_fork_epoch(&self) -> Option<Epoch> {
        None
    }

    /// Get the domain number, unmodified by the fork.
    ///
    /// Spec v0.11.1
    pub fn get_domain_constant(&self, domain: Domain) -> u32 {
        match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::BeaconAttester => self.domain_beacon_attester,
            Domain::Randao => self.domain_randao,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
            Domain::SelectionProof => self.domain_selection_proof,
            Domain::AggregateAndProof => self.domain_aggregate_and_proof,
        }
    }

    /// Get the domain that represents the fork meta and signature domain.
    ///
    /// Spec v0.11.1
    pub fn get_domain(
        &self,
        epoch: Epoch,
        domain: Domain,
        fork: &Fork,
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        let fork_version = fork.get_fork_version(epoch);
        self.compute_domain(domain, fork_version, genesis_validators_root)
    }

    /// Get the domain for a deposit signature.
    ///
    /// Deposits are valid across forks, thus the deposit domain is computed
    /// with the genesis fork version.
    ///
    /// Spec v0.11.1
    pub fn get_deposit_domain(&self) -> Hash256 {
        self.compute_domain(Domain::Deposit, self.genesis_fork_version, Hash256::zero())
    }

    /// Return the 32-byte fork data root for the `current_version` and `genesis_validators_root`.
    ///
    /// This is used primarily in signature domains to avoid collisions across forks/chains.
    ///
    /// Spec v0.11.1
    pub fn compute_fork_data_root(
        current_version: [u8; 4],
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        ForkData {
            current_version,
            genesis_validators_root,
        }
        .tree_hash_root()
    }

    /// Return the 4-byte fork digest for the `current_version` and `genesis_validators_root`.
    ///
    /// This is a digest primarily used for domain separation on the p2p layer.
    /// 4-bytes suffices for practical separation of forks/chains.
    pub fn compute_fork_digest(
        current_version: [u8; 4],
        genesis_validators_root: Hash256,
    ) -> [u8; 4] {
        let mut result = [0; 4];
        let root = Self::compute_fork_data_root(current_version, genesis_validators_root);
        result.copy_from_slice(&root.as_bytes()[0..4]);
        result
    }

    /// Compute a domain by applying the given `fork_version`.
    ///
    /// Spec v0.11.1
    pub fn compute_domain(
        &self,
        domain: Domain,
        fork_version: [u8; 4],
        genesis_validators_root: Hash256,
    ) -> Hash256 {
        let domain_constant = self.get_domain_constant(domain);

        let mut domain = [0; 32];
        domain[0..4].copy_from_slice(&int_to_bytes4(domain_constant));
        domain[4..].copy_from_slice(
            &Self::compute_fork_data_root(fork_version, genesis_validators_root)[..28],
        );

        Hash256::from(domain)
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    ///
    /// Spec v0.11.1
    pub fn mainnet() -> Self {
        Self {
            /*
             * Constants
             */
            genesis_slot: Slot::new(0),
            far_future_epoch: Epoch::new(u64::max_value()),
            base_rewards_per_epoch: 4,
            deposit_contract_tree_depth: 32,

            /*
             * Misc
             */
            max_committees_per_slot: 64,
            target_committee_size: 128,
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            shuffle_round_count: 90,
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_578_009_600, // Jan 3, 2020
            hysteresis_quotient: 4,
            hysteresis_downward_multiplier: 1,
            hysteresis_upward_multiplier: 5,

            /*
             *  Gwei values
             */
            min_deposit_amount: u64::pow(2, 0).saturating_mul(u64::pow(10, 9)),
            max_effective_balance: u64::pow(2, 5).saturating_mul(u64::pow(10, 9)),
            ejection_balance: u64::pow(2, 4).saturating_mul(u64::pow(10, 9)),
            effective_balance_increment: u64::pow(2, 0).saturating_mul(u64::pow(10, 9)),

            /*
             * Initial Values
             */
            genesis_fork_version: [0; 4],
            bls_withdrawal_prefix_byte: 0,

            /*
             * Time parameters
             */
            min_genesis_delay: 86400, // 1 day
            milliseconds_per_slot: 12_000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            persistent_committee_period: 2_048,

            /*
             * Reward and penalty quotients
             */
            base_reward_factor: 64,
            whistleblower_reward_quotient: 512,
            proposer_reward_quotient: 8,
            inactivity_penalty_quotient: 33_554_432,
            min_slashing_penalty_quotient: 32,

            /*
             * Signature domains
             */
            domain_beacon_proposer: 0,
            domain_beacon_attester: 1,
            domain_randao: 2,
            domain_deposit: 3,
            domain_voluntary_exit: 4,
            domain_selection_proof: 5,
            domain_aggregate_and_proof: 6,

            /*
             * Fork choice
             */
            safe_slots_to_update_justified: 8,

            /*
             * Eth1
             */
            eth1_follow_distance: 1_024,
            seconds_per_eth1_block: 14,

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 1, // mainnet network id
            attestation_propagation_slot_range: 32,
            attestation_subnet_count: 64,
            random_subnets_per_validator: 1,
            maximum_gossip_clock_disparity_millis: 500,
            target_aggregators_per_committee: 16,
            epochs_per_random_subnet_subscription: 256,
        }
    }

    /// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
    ///
    /// Spec v0.11.1
    pub fn minimal() -> Self {
        // Note: bootnodes to be updated when static nodes exist.
        let boot_nodes = vec![];

        Self {
            max_committees_per_slot: 4,
            target_committee_size: 4,
            shuffle_round_count: 10,
            min_genesis_active_validator_count: 64,
            eth1_follow_distance: 16,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
            persistent_committee_period: 128,
            min_genesis_delay: 300,
            milliseconds_per_slot: 6_000,
            safe_slots_to_update_justified: 2,
            network_id: 2, // lighthouse testnet network id
            boot_nodes,
            ..ChainSpec::mainnet()
        }
    }

    /// Interop testing spec
    ///
    /// This allows us to customize a chain spec for interop testing.
    pub fn interop() -> Self {
        let boot_nodes = vec![];

        Self {
            milliseconds_per_slot: 12_000,
            target_committee_size: 4,
            shuffle_round_count: 10,
            network_id: 13,
            boot_nodes,
            ..ChainSpec::mainnet()
        }
    }
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self::mainnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_spec_can_be_constructed() {
        let _ = ChainSpec::mainnet();
    }

    fn test_domain(domain_type: Domain, raw_domain: u32, spec: &ChainSpec) {
        let previous_version = [0, 0, 0, 1];
        let current_version = [0, 0, 0, 2];
        let genesis_validators_root = Hash256::from_low_u64_le(77);
        let fork_epoch = Epoch::new(1024);
        let fork = Fork {
            previous_version,
            current_version,
            epoch: fork_epoch,
        };

        for (epoch, version) in vec![
            (fork_epoch - 1, previous_version),
            (fork_epoch, current_version),
            (fork_epoch + 1, current_version),
        ] {
            let domain1 = spec.get_domain(epoch, domain_type, &fork, genesis_validators_root);
            let domain2 = spec.compute_domain(domain_type, version, genesis_validators_root);

            assert_eq!(domain1, domain2);
            assert_eq!(&domain1.as_bytes()[0..4], &int_to_bytes4(raw_domain)[..]);
        }
    }

    #[test]
    fn test_get_domain() {
        let spec = ChainSpec::mainnet();

        test_domain(Domain::BeaconProposer, spec.domain_beacon_proposer, &spec);
        test_domain(Domain::BeaconAttester, spec.domain_beacon_attester, &spec);
        test_domain(Domain::Randao, spec.domain_randao, &spec);
        test_domain(Domain::Deposit, spec.domain_deposit, &spec);
        test_domain(Domain::VoluntaryExit, spec.domain_voluntary_exit, &spec);
        test_domain(Domain::SelectionProof, spec.domain_selection_proof, &spec);
        test_domain(
            Domain::AggregateAndProof,
            spec.domain_aggregate_and_proof,
            &spec,
        );
    }
}

/// Union of a ChainSpec struct and an EthSpec struct that holds constants used for the configs
/// from the Ethereum 2 specs repo (https://github.com/ethereum/eth2.0-specs/tree/dev/configs)
///
/// Doesn't include fields of the YAML that we don't need yet (e.g. Phase 1 stuff).
///
/// Spec v0.11.1
// Yaml Config is declared here in order to access domain fields of ChainSpec which are private.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
pub struct YamlConfig {
    // ChainSpec
    far_future_epoch: u64,
    base_rewards_per_epoch: u64,
    deposit_contract_tree_depth: u64,
    max_committees_per_slot: usize,
    target_committee_size: usize,
    min_per_epoch_churn_limit: u64,
    churn_limit_quotient: u64,
    shuffle_round_count: u8,
    min_genesis_active_validator_count: u64,
    min_genesis_time: u64,
    min_genesis_delay: u64,
    min_deposit_amount: u64,
    max_effective_balance: u64,
    ejection_balance: u64,
    effective_balance_increment: u64,
    hysteresis_quotient: u64,
    hysteresis_downward_multiplier: u64,
    hysteresis_upward_multiplier: u64,
    genesis_slot: u64,
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    genesis_fork_version: [u8; 4],
    #[serde(deserialize_with = "u8_from_hex_str", serialize_with = "u8_to_hex_str")]
    bls_withdrawal_prefix: u8,
    seconds_per_slot: u64,
    min_attestation_inclusion_delay: u64,
    min_seed_lookahead: u64,
    max_seed_lookahead: u64,
    min_epochs_to_inactivity_penalty: u64,
    min_validator_withdrawability_delay: u64,
    persistent_committee_period: u64,
    base_reward_factor: u64,
    whistleblower_reward_quotient: u64,
    proposer_reward_quotient: u64,
    inactivity_penalty_quotient: u64,
    min_slashing_penalty_quotient: u64,
    safe_slots_to_update_justified: u64,

    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_beacon_proposer: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_beacon_attester: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_randao: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_deposit: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_voluntary_exit: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_selection_proof: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    domain_aggregate_and_proof: u32,
    #[serde(
        deserialize_with = "u32_from_hex_str",
        serialize_with = "u32_to_hex_str"
    )]
    // EthSpec
    justification_bits_length: u32,
    max_validators_per_committee: u32,
    genesis_epoch: Epoch,
    slots_per_epoch: u64,
    epochs_per_eth1_voting_period: u64,
    slots_per_historical_root: usize,
    epochs_per_historical_vector: usize,
    epochs_per_slashings_vector: usize,
    historical_roots_limit: u64,
    validator_registry_limit: u64,
    max_proposer_slashings: u32,
    max_attester_slashings: u32,
    max_attestations: u32,
    max_deposits: u32,
    max_voluntary_exits: u32,

    // Validator
    eth1_follow_distance: u64,
    target_aggregators_per_committee: u64,
    random_subnets_per_validator: u64,
    epochs_per_random_subnet_subscription: u64,
    seconds_per_eth1_block: u64,
}

impl Default for YamlConfig {
    fn default() -> Self {
        let chain_spec = MainnetEthSpec::default_spec();
        YamlConfig::from_spec::<MainnetEthSpec>(&chain_spec)
    }
}

/// Spec v0.11.1
impl YamlConfig {
    #[allow(clippy::integer_arithmetic)]
    pub fn from_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        Self {
            // ChainSpec
            far_future_epoch: spec.far_future_epoch.into(),
            base_rewards_per_epoch: spec.base_rewards_per_epoch,
            deposit_contract_tree_depth: spec.deposit_contract_tree_depth,
            max_committees_per_slot: spec.max_committees_per_slot,
            target_committee_size: spec.target_committee_size,
            min_per_epoch_churn_limit: spec.min_per_epoch_churn_limit,
            churn_limit_quotient: spec.churn_limit_quotient,
            shuffle_round_count: spec.shuffle_round_count,
            min_genesis_active_validator_count: spec.min_genesis_active_validator_count,
            min_genesis_time: spec.min_genesis_time,
            min_genesis_delay: spec.min_genesis_delay,
            min_deposit_amount: spec.min_deposit_amount,
            max_effective_balance: spec.max_effective_balance,
            ejection_balance: spec.ejection_balance,
            effective_balance_increment: spec.effective_balance_increment,
            hysteresis_quotient: spec.hysteresis_quotient,
            hysteresis_downward_multiplier: spec.hysteresis_downward_multiplier,
            hysteresis_upward_multiplier: spec.hysteresis_upward_multiplier,
            genesis_slot: spec.genesis_slot.into(),
            bls_withdrawal_prefix: spec.bls_withdrawal_prefix_byte,
            seconds_per_slot: spec.milliseconds_per_slot / 1000,
            min_attestation_inclusion_delay: spec.min_attestation_inclusion_delay,
            min_seed_lookahead: spec.min_seed_lookahead.into(),
            max_seed_lookahead: spec.max_seed_lookahead.into(),
            min_validator_withdrawability_delay: spec.min_validator_withdrawability_delay.into(),
            persistent_committee_period: spec.persistent_committee_period,
            min_epochs_to_inactivity_penalty: spec.min_epochs_to_inactivity_penalty,
            base_reward_factor: spec.base_reward_factor,
            whistleblower_reward_quotient: spec.whistleblower_reward_quotient,
            proposer_reward_quotient: spec.proposer_reward_quotient,
            inactivity_penalty_quotient: spec.inactivity_penalty_quotient,
            min_slashing_penalty_quotient: spec.min_slashing_penalty_quotient,
            genesis_fork_version: spec.genesis_fork_version,
            safe_slots_to_update_justified: spec.safe_slots_to_update_justified,
            domain_beacon_proposer: spec.domain_beacon_proposer,
            domain_beacon_attester: spec.domain_beacon_attester,
            domain_randao: spec.domain_randao,
            domain_deposit: spec.domain_deposit,
            domain_voluntary_exit: spec.domain_voluntary_exit,
            domain_selection_proof: spec.domain_selection_proof,
            domain_aggregate_and_proof: spec.domain_aggregate_and_proof,

            // EthSpec
            justification_bits_length: T::JustificationBitsLength::to_u32(),
            max_validators_per_committee: T::MaxValidatorsPerCommittee::to_u32(),
            genesis_epoch: T::genesis_epoch(),
            slots_per_epoch: T::slots_per_epoch(),
            epochs_per_eth1_voting_period: T::EpochsPerEth1VotingPeriod::to_u64(),
            slots_per_historical_root: T::slots_per_historical_root(),
            epochs_per_historical_vector: T::epochs_per_historical_vector(),
            epochs_per_slashings_vector: T::EpochsPerSlashingsVector::to_usize(),
            historical_roots_limit: T::HistoricalRootsLimit::to_u64(),
            validator_registry_limit: T::ValidatorRegistryLimit::to_u64(),
            max_proposer_slashings: T::MaxProposerSlashings::to_u32(),
            max_attester_slashings: T::MaxAttesterSlashings::to_u32(),
            max_attestations: T::MaxAttestations::to_u32(),
            max_deposits: T::MaxDeposits::to_u32(),
            max_voluntary_exits: T::MaxVoluntaryExits::to_u32(),

            // Validator
            eth1_follow_distance: spec.eth1_follow_distance,
            target_aggregators_per_committee: spec.target_aggregators_per_committee,
            random_subnets_per_validator: spec.random_subnets_per_validator,
            epochs_per_random_subnet_subscription: spec.epochs_per_random_subnet_subscription,
            seconds_per_eth1_block: spec.seconds_per_eth1_block,
        }
    }

    pub fn from_file(filename: &Path) -> Result<Self, String> {
        let f = File::open(filename)
            .map_err(|e| format!("Error opening spec at {}: {:?}", filename.display(), e))?;
        serde_yaml::from_reader(f)
            .map_err(|e| format!("Error parsing spec at {}: {:?}", filename.display(), e))
    }

    pub fn apply_to_chain_spec<T: EthSpec>(&self, chain_spec: &ChainSpec) -> Option<ChainSpec> {
        // Checking for EthSpec constants
        if self.justification_bits_length != T::JustificationBitsLength::to_u32()
            || self.max_validators_per_committee != T::MaxValidatorsPerCommittee::to_u32()
            || self.genesis_epoch != T::genesis_epoch()
            || self.slots_per_epoch != T::slots_per_epoch()
            || self.epochs_per_eth1_voting_period != T::EpochsPerEth1VotingPeriod::to_u64()
            || self.slots_per_historical_root != T::slots_per_historical_root()
            || self.epochs_per_historical_vector != T::epochs_per_historical_vector()
            || self.epochs_per_slashings_vector != T::EpochsPerSlashingsVector::to_usize()
            || self.historical_roots_limit != T::HistoricalRootsLimit::to_u64()
            || self.validator_registry_limit != T::ValidatorRegistryLimit::to_u64()
            || self.max_proposer_slashings != T::MaxProposerSlashings::to_u32()
            || self.max_attester_slashings != T::MaxAttesterSlashings::to_u32()
            || self.max_attestations != T::MaxAttestations::to_u32()
            || self.max_deposits != T::MaxDeposits::to_u32()
            || self.max_voluntary_exits != T::MaxVoluntaryExits::to_u32()
        {
            return None;
        }

        // Create a ChainSpec from the yaml config
        Some(ChainSpec {
            far_future_epoch: Epoch::from(self.far_future_epoch),
            base_rewards_per_epoch: self.base_rewards_per_epoch,
            deposit_contract_tree_depth: self.deposit_contract_tree_depth,
            target_committee_size: self.target_committee_size,
            min_per_epoch_churn_limit: self.min_per_epoch_churn_limit,
            churn_limit_quotient: self.churn_limit_quotient,
            shuffle_round_count: self.shuffle_round_count,
            min_genesis_active_validator_count: self.min_genesis_active_validator_count,
            min_genesis_time: self.min_genesis_time,
            min_deposit_amount: self.min_deposit_amount,
            min_genesis_delay: self.min_genesis_delay,
            max_effective_balance: self.max_effective_balance,
            hysteresis_quotient: self.hysteresis_quotient,
            hysteresis_downward_multiplier: self.hysteresis_downward_multiplier,
            hysteresis_upward_multiplier: self.hysteresis_upward_multiplier,
            ejection_balance: self.ejection_balance,
            effective_balance_increment: self.effective_balance_increment,
            genesis_slot: Slot::from(self.genesis_slot),
            bls_withdrawal_prefix_byte: self.bls_withdrawal_prefix,
            milliseconds_per_slot: self.seconds_per_slot.saturating_mul(1000),
            min_attestation_inclusion_delay: self.min_attestation_inclusion_delay,
            min_seed_lookahead: Epoch::from(self.min_seed_lookahead),
            max_seed_lookahead: Epoch::from(self.max_seed_lookahead),
            min_validator_withdrawability_delay: Epoch::from(
                self.min_validator_withdrawability_delay,
            ),
            persistent_committee_period: self.persistent_committee_period,
            min_epochs_to_inactivity_penalty: self.min_epochs_to_inactivity_penalty,
            base_reward_factor: self.base_reward_factor,
            whistleblower_reward_quotient: self.whistleblower_reward_quotient,
            proposer_reward_quotient: self.proposer_reward_quotient,
            inactivity_penalty_quotient: self.inactivity_penalty_quotient,
            min_slashing_penalty_quotient: self.min_slashing_penalty_quotient,
            domain_beacon_proposer: self.domain_beacon_proposer,
            domain_beacon_attester: self.domain_beacon_attester,
            domain_randao: self.domain_randao,
            domain_deposit: self.domain_deposit,
            domain_voluntary_exit: self.domain_voluntary_exit,
            boot_nodes: chain_spec.boot_nodes.clone(),
            genesis_fork_version: self.genesis_fork_version,
            eth1_follow_distance: self.eth1_follow_distance,
            ..*chain_spec
        })
    }
}

#[cfg(test)]
mod yaml_tests {
    use super::*;
    use std::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[test]
    fn minimal_round_trip() {
        // create temp file
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let minimal_spec = ChainSpec::minimal();

        let yamlconfig = YamlConfig::from_spec::<MinimalEthSpec>(&minimal_spec);
        // write fresh minimal config to file
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        // deserialize minimal config from file
        let from: YamlConfig = serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn mainnet_round_trip() {
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let mainnet_spec = ChainSpec::mainnet();
        let yamlconfig = YamlConfig::from_spec::<MainnetEthSpec>(&mainnet_spec);
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: YamlConfig = serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn apply_to_spec() {
        let mut spec = ChainSpec::minimal();
        let yamlconfig = YamlConfig::from_spec::<MinimalEthSpec>(&spec);

        // modifying the original spec
        spec.deposit_contract_tree_depth += 1;
        // Applying a yaml config with incorrect EthSpec should fail
        let res = yamlconfig.apply_to_chain_spec::<MainnetEthSpec>(&spec);
        assert_eq!(res, None);

        // Applying a yaml config with correct EthSpec should NOT fail
        let new_spec = yamlconfig
            .apply_to_chain_spec::<MinimalEthSpec>(&spec)
            .expect("should have applied spec");
        assert_eq!(new_spec, ChainSpec::minimal());
    }
}
