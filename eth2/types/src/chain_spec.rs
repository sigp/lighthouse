use crate::*;
use int_to_bytes::int_to_bytes4;
use serde_derive::{Deserialize, Serialize};
use utils::{u32_from_hex_str, u32_to_hex_str, u8_from_hex_str, u8_to_hex_str};

/// Each of the BLS signature domains.
///
/// Spec v0.9.1
pub enum Domain {
    BeaconProposer,
    BeaconAttester,
    Randao,
    Deposit,
    VoluntaryExit,
}

/// Holds all the "constants" for a BeaconChain.
///
/// Spec v0.9.1
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChainSpec {
    /*
     * Constants
     */
    #[serde(skip_serializing)] // skipped because Serde TOML has trouble with u64::max
    pub far_future_epoch: Epoch,
    pub base_rewards_per_epoch: u64,
    pub deposit_contract_tree_depth: u64,
    pub seconds_per_day: u64,

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
    #[serde(deserialize_with = "u8_from_hex_str", serialize_with = "u8_to_hex_str")]
    pub bls_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub milliseconds_per_slot: u64,
    pub min_attestation_inclusion_delay: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_validator_withdrawability_delay: Epoch,
    pub persistent_committee_period: u64,
    pub min_epochs_to_inactivity_penalty: u64,

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

    /*
     * Fork choice
     */
    pub safe_slots_to_update_justified: u64,

    /*
     * Eth1
     */
    pub eth1_follow_distance: u64,

    pub boot_nodes: Vec<String>,
    pub network_id: u8,

    pub genesis_fork: Fork,
}

impl ChainSpec {
    /// Get the domain number, unmodified by the fork.
    ///
    /// Spec v0.9.1
    pub fn get_domain_constant(&self, domain: Domain) -> u32 {
        match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::BeaconAttester => self.domain_beacon_attester,
            Domain::Randao => self.domain_randao,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
        }
    }

    /// Get the domain number that represents the fork meta and signature domain.
    ///
    /// Spec v0.9.1
    pub fn get_domain(&self, epoch: Epoch, domain: Domain, fork: &Fork) -> u64 {
        let domain_constant = self.get_domain_constant(domain);

        let mut bytes: Vec<u8> = int_to_bytes4(domain_constant);
        bytes.append(&mut fork.get_fork_version(epoch).to_vec());

        let mut fork_and_domain = [0; 8];
        fork_and_domain.copy_from_slice(&bytes);

        u64::from_le_bytes(fork_and_domain)
    }

    /// Get the domain for a deposit signature.
    ///
    /// Deposits are valid across forks, thus the deposit domain is computed
    /// with the fork zeroed.
    ///
    /// Spec v0.8.1
    pub fn get_deposit_domain(&self) -> u64 {
        let mut bytes: Vec<u8> = int_to_bytes4(self.domain_deposit);
        bytes.append(&mut vec![0; 4]);

        let mut fork_and_domain = [0; 8];
        fork_and_domain.copy_from_slice(&bytes);

        u64::from_le_bytes(fork_and_domain)
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    ///
    /// Spec v0.9.1
    pub fn mainnet() -> Self {
        Self {
            /*
             * Constants
             */
            far_future_epoch: Epoch::new(u64::max_value()),
            base_rewards_per_epoch: 4,
            deposit_contract_tree_depth: 32,
            seconds_per_day: 86400,

            /*
             * Misc
             */
            max_committees_per_slot: 64,
            target_committee_size: 128,
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            shuffle_round_count: 90,
            min_genesis_active_validator_count: 65_536,
            min_genesis_time: 1_578_009_600, // Jan 3, 2020

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
            bls_withdrawal_prefix_byte: 0,

            /*
             * Time parameters
             */
            milliseconds_per_slot: 12_000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_validator_withdrawability_delay: Epoch::new(256),
            persistent_committee_period: 2_048,
            min_epochs_to_inactivity_penalty: 4,

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

            /*
             * Fork choice
             */
            safe_slots_to_update_justified: 8,

            /*
             * Eth1
             */
            eth1_follow_distance: 1_024,

            /*
             * Fork
             */
            genesis_fork: Fork {
                previous_version: [0; 4],
                current_version: [0; 4],
                epoch: Epoch::new(0),
            },

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 1, // mainnet network id
        }
    }

    /// Ethereum Foundation minimal spec, as defined here:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/configs/minimal.yaml
    ///
    /// Spec v0.9.1
    pub fn minimal() -> Self {
        // Note: bootnodes to be updated when static nodes exist.
        let boot_nodes = vec![];

        Self {
            max_committees_per_slot: 4,
            target_committee_size: 4,
            shuffle_round_count: 10,
            min_genesis_active_validator_count: 64,
            network_id: 2, // lighthouse testnet network id
            boot_nodes,
            eth1_follow_distance: 16,
            milliseconds_per_slot: 6_000,
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
    use int_to_bytes::int_to_bytes8;

    #[test]
    fn test_mainnet_spec_can_be_constructed() {
        let _ = ChainSpec::mainnet();
    }

    fn test_domain(domain_type: Domain, raw_domain: u32, spec: &ChainSpec) {
        let fork = &spec.genesis_fork;
        let epoch = Epoch::new(0);

        let domain = spec.get_domain(epoch, domain_type, &fork);

        let mut expected = int_to_bytes4(raw_domain);
        expected.append(&mut fork.get_fork_version(epoch).to_vec());

        assert_eq!(int_to_bytes8(domain), expected);
    }

    #[test]
    fn test_get_domain() {
        let spec = ChainSpec::mainnet();

        test_domain(Domain::BeaconProposer, spec.domain_beacon_proposer, &spec);
        test_domain(Domain::BeaconAttester, spec.domain_beacon_attester, &spec);
        test_domain(Domain::Randao, spec.domain_randao, &spec);
        test_domain(Domain::Deposit, spec.domain_deposit, &spec);
        test_domain(Domain::VoluntaryExit, spec.domain_voluntary_exit, &spec);
    }
}

// Yaml Config is declared here in order to access domain fields of ChainSpec which are private fields.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
#[serde(deny_unknown_fields)]
/// Union of a ChainSpec struct and an EthSpec struct that holds constants used for the configs folder of the Ethereum 2 spec (https://github.com/ethereum/eth2.0-specs/tree/dev/configs)
/// Spec v0.9.1
pub struct YamlConfig {
    // ChainSpec
    far_future_epoch: u64,
    base_rewards_per_epoch: u64,
    deposit_contract_tree_depth: u64,
    seconds_per_day: u64,
    max_committees_per_slot: usize,
    target_committee_size: usize,
    min_per_epoch_churn_limit: u64,
    churn_limit_quotient: u64,
    shuffle_round_count: u8,
    min_genesis_active_validator_count: u64,
    min_genesis_time: u64,
    min_deposit_amount: u64,
    max_effective_balance: u64,
    ejection_balance: u64,
    effective_balance_increment: u64,
    genesis_slot: u64,
    #[serde(deserialize_with = "u8_from_hex_str", serialize_with = "u8_to_hex_str")]
    bls_withdrawal_prefix: u8,
    seconds_per_slot: u64,
    min_attestation_inclusion_delay: u64,
    min_seed_lookahead: u64,
    min_validator_withdrawability_delay: u64,
    persistent_committee_period: u64,
    min_epochs_to_inactivity_penalty: u64,
    base_reward_factor: u64,
    whistleblower_reward_quotient: u64,
    proposer_reward_quotient: u64,
    inactivity_penalty_quotient: u64,
    min_slashing_penalty_quotient: u64,
    safe_slots_to_update_justified: u64,

    #[serde(skip_serializing)]
    genesis_fork: Fork,

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
    // EthSpec
    justification_bits_length: u32,
    max_validators_per_committee: u32,
    genesis_epoch: Epoch,
    slots_per_epoch: u64,
    slots_per_eth1_voting_period: usize,
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

    // Unused
    #[serde(skip_serializing)]
    early_derived_secret_penalty_max_future_epochs: u32,
    #[serde(skip_serializing)]
    max_seed_lookahead: u32,
    #[serde(skip_serializing)]
    deposit_contract_address: String,

    // Phase 1
    #[serde(skip_serializing)]
    epochs_per_custody_period: u32,
    #[serde(skip_serializing)]
    custody_period_to_randao_padding: u32,
    #[serde(skip_serializing)]
    shard_slots_per_beacon_slot: u32,
    #[serde(skip_serializing)]
    epochs_per_shard_period: u32,
    #[serde(skip_serializing)]
    phase_1_fork_epoch: u32,
    #[serde(skip_serializing)]
    phase_1_fork_slot: u32,
    #[serde(skip_serializing)]
    domain_custody_bit_challenge: u32,
    #[serde(skip_serializing)]
    domain_shard_proposer: u32,
    #[serde(skip_serializing)]
    domain_shard_attester: u32,
    #[serde(skip_serializing)]
    max_epochs_per_crosslink: u64,
}

impl Default for YamlConfig {
    fn default() -> Self {
        let chain_spec = MainnetEthSpec::default_spec();
        YamlConfig::from_spec::<MainnetEthSpec>(&chain_spec)
    }
}

/// Spec v0.8.1
impl YamlConfig {
    pub fn from_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        Self {
            // ChainSpec
            far_future_epoch: spec.far_future_epoch.into(),
            base_rewards_per_epoch: spec.base_rewards_per_epoch,
            deposit_contract_tree_depth: spec.deposit_contract_tree_depth,
            seconds_per_day: spec.seconds_per_day,
            max_committees_per_slot: spec.max_committees_per_slot,
            target_committee_size: spec.target_committee_size,
            min_per_epoch_churn_limit: spec.min_per_epoch_churn_limit,
            churn_limit_quotient: spec.churn_limit_quotient,
            shuffle_round_count: spec.shuffle_round_count,
            min_genesis_active_validator_count: spec.min_genesis_active_validator_count,
            min_genesis_time: spec.min_genesis_time,
            min_deposit_amount: spec.min_deposit_amount,
            max_effective_balance: spec.max_effective_balance,
            ejection_balance: spec.ejection_balance,
            effective_balance_increment: spec.effective_balance_increment,
            genesis_slot: spec.genesis_slot.into(),
            bls_withdrawal_prefix: spec.bls_withdrawal_prefix_byte,
            seconds_per_slot: spec.milliseconds_per_slot / 1000,
            min_attestation_inclusion_delay: spec.min_attestation_inclusion_delay,
            min_seed_lookahead: spec.min_seed_lookahead.into(),
            min_validator_withdrawability_delay: spec.min_validator_withdrawability_delay.into(),
            persistent_committee_period: spec.persistent_committee_period,
            min_epochs_to_inactivity_penalty: spec.min_epochs_to_inactivity_penalty,
            base_reward_factor: spec.base_reward_factor,
            whistleblower_reward_quotient: spec.whistleblower_reward_quotient,
            proposer_reward_quotient: spec.proposer_reward_quotient,
            inactivity_penalty_quotient: spec.inactivity_penalty_quotient,
            min_slashing_penalty_quotient: spec.min_slashing_penalty_quotient,
            genesis_fork: spec.genesis_fork.clone(),
            safe_slots_to_update_justified: spec.safe_slots_to_update_justified,
            domain_beacon_proposer: spec.domain_beacon_proposer,
            domain_beacon_attester: spec.domain_beacon_attester,
            domain_randao: spec.domain_randao,
            domain_deposit: spec.domain_deposit,
            domain_voluntary_exit: spec.domain_voluntary_exit,

            // EthSpec
            justification_bits_length: T::JustificationBitsLength::to_u32(),
            max_validators_per_committee: T::MaxValidatorsPerCommittee::to_u32(),
            genesis_epoch: T::genesis_epoch(),
            slots_per_epoch: T::slots_per_epoch(),
            slots_per_eth1_voting_period: T::slots_per_eth1_voting_period(),
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

            // Unused
            early_derived_secret_penalty_max_future_epochs: 0,
            max_seed_lookahead: 0,
            deposit_contract_address: String::new(),

            // Phase 1
            epochs_per_custody_period: 0,
            custody_period_to_randao_padding: 0,
            shard_slots_per_beacon_slot: 0,
            epochs_per_shard_period: 0,
            phase_1_fork_epoch: 0,
            phase_1_fork_slot: 0,
            domain_custody_bit_challenge: 0,
            domain_shard_proposer: 0,
            domain_shard_attester: 0,
            max_epochs_per_crosslink: 0,
        }
    }

    pub fn apply_to_chain_spec<T: EthSpec>(&self, chain_spec: &ChainSpec) -> Option<ChainSpec> {
        // Checking for EthSpec constants
        if self.justification_bits_length != T::JustificationBitsLength::to_u32()
            || self.max_validators_per_committee != T::MaxValidatorsPerCommittee::to_u32()
            || self.genesis_epoch != T::genesis_epoch()
            || self.slots_per_epoch != T::slots_per_epoch()
            || self.slots_per_eth1_voting_period != T::slots_per_eth1_voting_period()
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
            seconds_per_day: self.seconds_per_day,
            target_committee_size: self.target_committee_size,
            min_per_epoch_churn_limit: self.min_per_epoch_churn_limit,
            churn_limit_quotient: self.churn_limit_quotient,
            shuffle_round_count: self.shuffle_round_count,
            min_genesis_active_validator_count: self.min_genesis_active_validator_count,
            min_genesis_time: self.min_genesis_time,
            min_deposit_amount: self.min_deposit_amount,
            max_effective_balance: self.max_effective_balance,
            ejection_balance: self.ejection_balance,
            effective_balance_increment: self.effective_balance_increment,
            genesis_slot: Slot::from(self.genesis_slot),
            bls_withdrawal_prefix_byte: self.bls_withdrawal_prefix,
            milliseconds_per_slot: self.seconds_per_slot * 1000,
            min_attestation_inclusion_delay: self.min_attestation_inclusion_delay,
            min_seed_lookahead: Epoch::from(self.min_seed_lookahead),
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
            domain_randao: self.domain_randao,
            domain_deposit: self.domain_deposit,
            domain_voluntary_exit: self.domain_voluntary_exit,
            boot_nodes: chain_spec.boot_nodes.clone(),
            genesis_fork: chain_spec.genesis_fork.clone(),
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
