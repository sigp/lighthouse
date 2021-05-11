//! This file contains several different representations of the beacon chain configuration
//! parameters.
//!
//! Arguably the most import of these is `ChainSpec`, which is used throughout Lighthouse as the
//! source-of-truth regarding spec-level configuration.
//!
//! The other types exist for interoperability with other systems. The `StandardConfig` is an object
//! intended to match an EF spec configuration (usually YAML), and is broken into sub-parts for
//! each relevant fork. It is also serialised as JSON for the standardised HTTP API.
use crate::*;
use int_to_bytes::int_to_bytes4;
use serde_derive::{Deserialize, Serialize};
use serde_utils::quoted_u64::MaybeQuoted;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use tree_hash::TreeHash;

/// Each of the BLS signature domains.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Domain {
    BeaconProposer,
    BeaconAttester,
    Randao,
    Deposit,
    VoluntaryExit,
    SelectionProof,
    AggregateAndProof,
    SyncCommittee,
}

/// Holds all the "constants" for a BeaconChain.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Debug, Clone)]
pub struct ChainSpec {
    /*
     * Constants
     */
    pub genesis_slot: Slot,
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
    pub proportional_slashing_multiplier: u64,

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
    pub genesis_fork_version: [u8; 4],
    pub bls_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub genesis_delay: u64,
    pub seconds_per_slot: u64,
    pub min_attestation_inclusion_delay: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_epochs_to_inactivity_penalty: u64,
    pub min_validator_withdrawability_delay: Epoch,
    pub shard_committee_period: u64,

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
    pub deposit_chain_id: u64,
    pub deposit_network_id: u64,
    pub deposit_contract_address: Address,

    /*
     * Altair hard fork params
     */
    pub inactivity_penalty_quotient_altair: u64,
    pub min_slashing_penalty_quotient_altair: u64,
    pub proportional_slashing_multiplier_altair: u64,
    pub epochs_per_sync_committee_period: Epoch,
    pub inactivity_score_bias: u64,
    domain_sync_committee: u32,
    domain_sync_committee_selection_proof: u32,
    domain_contribution_and_proof: u32,
    pub altair_fork_version: [u8; 4],
    /// The Altair fork slot is optional, with `None` representing "Altair never happens".
    pub altair_fork_slot: Option<Slot>,

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
    /// Construct a `ChainSpec` from a standard config.
    pub fn from_standard_config<T: EthSpec>(standard_config: &StandardConfig) -> Option<Self> {
        let mut spec = T::default_spec();
        spec = standard_config.base().apply_to_chain_spec::<T>(&spec)?;

        if let Ok(altair) = standard_config.altair() {
            spec = altair.apply_to_chain_spec::<T>(&spec)?;
        }
        Some(spec)
    }

    /// Returns an `EnrForkId` for the given `slot`.
    pub fn enr_fork_id(&self, slot: Slot, genesis_validators_root: Hash256) -> EnrForkId {
        EnrForkId {
            fork_digest: self.fork_digest(slot, genesis_validators_root),
            next_fork_version: self.genesis_fork_version,
            next_fork_epoch: self.far_future_epoch,
        }
    }

    /// Returns the `ForkDigest` for the given slot.
    ///
    /// If `self.altair_fork_slot == None`, then this function returns the genesis fork digest
    /// otherwise, returns the fork digest based on the slot.
    pub fn fork_digest(&self, slot: Slot, genesis_validators_root: Hash256) -> [u8; 4] {
        if let Some(altair_fork_slot) = self.altair_fork_slot {
            if slot >= altair_fork_slot {
                Self::compute_fork_digest(self.altair_fork_version, genesis_validators_root)
            } else {
                Self::compute_fork_digest(self.genesis_fork_version, genesis_validators_root)
            }
        } else {
            Self::compute_fork_digest(self.genesis_fork_version, genesis_validators_root)
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
    /// Spec v0.12.1
    pub fn get_domain_constant(&self, domain: Domain) -> u32 {
        match domain {
            Domain::BeaconProposer => self.domain_beacon_proposer,
            Domain::BeaconAttester => self.domain_beacon_attester,
            Domain::Randao => self.domain_randao,
            Domain::Deposit => self.domain_deposit,
            Domain::VoluntaryExit => self.domain_voluntary_exit,
            Domain::SelectionProof => self.domain_selection_proof,
            Domain::AggregateAndProof => self.domain_aggregate_and_proof,
            Domain::SyncCommittee => self.domain_sync_committee,
        }
    }

    /// Get the domain that represents the fork meta and signature domain.
    ///
    /// Spec v0.12.1
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
    /// Spec v0.12.1
    pub fn get_deposit_domain(&self) -> Hash256 {
        self.compute_domain(Domain::Deposit, self.genesis_fork_version, Hash256::zero())
    }

    /// Return the 32-byte fork data root for the `current_version` and `genesis_validators_root`.
    ///
    /// This is used primarily in signature domains to avoid collisions across forks/chains.
    ///
    /// Spec v0.12.1
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
        result.copy_from_slice(
            root.as_bytes()
                .get(0..4)
                .expect("root hash is at least 4 bytes"),
        );
        result
    }

    /// Compute a domain by applying the given `fork_version`.
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
            Self::compute_fork_data_root(fork_version, genesis_validators_root)
                .as_bytes()
                .get(..28)
                .expect("fork has is 32 bytes so first 28 bytes should exist"),
        );

        Hash256::from(domain)
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    ///
    /// Spec v0.12.3
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
            min_genesis_time: 1606824000, // Dec 1, 2020
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
            genesis_delay: 604800, // 7 days
            seconds_per_slot: 12,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            shard_committee_period: 256,

            /*
             * Reward and penalty quotients
             */
            base_reward_factor: 64,
            whistleblower_reward_quotient: 512,
            proposer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::pow(2, 26),
            min_slashing_penalty_quotient: 128,
            proportional_slashing_multiplier: 1,

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
            eth1_follow_distance: 2048,
            seconds_per_eth1_block: 14,
            deposit_chain_id: 1,
            deposit_network_id: 1,
            deposit_contract_address: "00000000219ab540356cbb839cbe05303d7705fa"
                .parse()
                .expect("chain spec deposit contract address"),

            /*
             * Altair hard fork params
             */
            inactivity_penalty_quotient_altair: u64::pow(2, 24).saturating_mul(3),
            min_slashing_penalty_quotient_altair: u64::pow(2, 6),
            proportional_slashing_multiplier_altair: 2,
            inactivity_score_bias: 4,
            epochs_per_sync_committee_period: Epoch::new(256),
            domain_sync_committee: 7,
            domain_sync_committee_selection_proof: 8,
            domain_contribution_and_proof: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            altair_fork_slot: Some(Slot::new(u64::MAX)),

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
    pub fn minimal() -> Self {
        // Note: bootnodes to be updated when static nodes exist.
        let boot_nodes = vec![];

        Self {
            max_committees_per_slot: 4,
            target_committee_size: 4,
            shuffle_round_count: 10,
            min_genesis_active_validator_count: 64,
            min_genesis_time: 1578009600,
            eth1_follow_distance: 16,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
            shard_committee_period: 64,
            genesis_delay: 300,
            seconds_per_slot: 6,
            inactivity_penalty_quotient: u64::pow(2, 25),
            min_slashing_penalty_quotient: 64,
            proportional_slashing_multiplier: 2,
            safe_slots_to_update_justified: 2,
            // Altair
            epochs_per_sync_committee_period: Epoch::new(8),
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            altair_fork_slot: Some(Slot::new(u64::MAX)),
            // Other
            network_id: 2, // lighthouse testnet network id
            deposit_chain_id: 5,
            deposit_network_id: 5,
            deposit_contract_address: "1234567890123456789012345678901234567890"
                .parse()
                .expect("minimal chain spec deposit address"),
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

/// Configuration struct for compatibility with the spec's .yaml configuration
///
/// Ordering of these enum variants is significant because it determines serde's deserialisation
/// priority. I.e. Altair before Base.
///
#[superstruct(
    variants(Altair, Base),
    variant_attributes(derive(Serialize, Deserialize, Debug, PartialEq, Clone))
)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub struct StandardConfig {
    #[serde(flatten)]
    pub base: BaseConfig,
    /// Configuration related to the Altair hard fork.
    #[superstruct(only(Altair))]
    #[serde(flatten)]
    pub altair: AltairConfig,

    /// The `extra_fields` map allows us to gracefully decode fields intended for future hard forks.
    #[serde(flatten)]
    pub extra_fields: HashMap<String, String>,
}

impl StandardConfig {
    pub fn from_chain_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        let base = BaseConfig::from_chain_spec::<T>(spec);
        let altair = AltairConfig::from_chain_spec::<T>(spec);
        Self::from_parts(base, altair)
    }

    pub fn from_parts(base: BaseConfig, altair: AltairConfig) -> Self {
        let extra_fields = HashMap::new();
        StandardConfig::Altair(StandardConfigAltair {
            base,
            altair,
            extra_fields,
        })
    }
}

/// Configuration related to the base/phase0/genesis fork (YAML/JSON version).
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct BaseConfig {
    pub config_name: String,
    // ChainSpec
    #[serde(with = "serde_utils::quoted_u64")]
    max_committees_per_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    target_committee_size: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_per_epoch_churn_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    churn_limit_quotient: u64,
    #[serde(with = "serde_utils::quoted_u8")]
    shuffle_round_count: u8,
    #[serde(with = "serde_utils::quoted_u64")]
    min_genesis_active_validator_count: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_genesis_time: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    genesis_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_deposit_amount: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    max_effective_balance: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    ejection_balance: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    effective_balance_increment: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    hysteresis_quotient: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    hysteresis_downward_multiplier: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    hysteresis_upward_multiplier: u64,
    #[serde(with = "serde_utils::bytes_4_hex")]
    genesis_fork_version: [u8; 4],
    #[serde(with = "serde_utils::u8_hex")]
    bls_withdrawal_prefix: u8,
    #[serde(with = "serde_utils::quoted_u64")]
    seconds_per_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_attestation_inclusion_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_seed_lookahead: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    max_seed_lookahead: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_epochs_to_inactivity_penalty: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_validator_withdrawability_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    shard_committee_period: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    base_reward_factor: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    whistleblower_reward_quotient: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    proposer_reward_quotient: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    inactivity_penalty_quotient: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_slashing_penalty_quotient: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    proportional_slashing_multiplier: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    safe_slots_to_update_justified: u64,

    #[serde(with = "serde_utils::u32_hex")]
    domain_beacon_proposer: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_beacon_attester: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_randao: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_deposit: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_voluntary_exit: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_selection_proof: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_aggregate_and_proof: u32,

    // EthSpec
    #[serde(with = "serde_utils::quoted_u32")]
    max_validators_per_committee: u32,
    #[serde(with = "serde_utils::quoted_u64")]
    slots_per_epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_eth1_voting_period: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    slots_per_historical_root: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_historical_vector: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_slashings_vector: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    historical_roots_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    validator_registry_limit: u64,
    #[serde(with = "serde_utils::quoted_u32")]
    max_proposer_slashings: u32,
    #[serde(with = "serde_utils::quoted_u32")]
    max_attester_slashings: u32,
    #[serde(with = "serde_utils::quoted_u32")]
    max_attestations: u32,
    #[serde(with = "serde_utils::quoted_u32")]
    max_deposits: u32,
    #[serde(with = "serde_utils::quoted_u32")]
    max_voluntary_exits: u32,
    // Validator
    #[serde(with = "serde_utils::quoted_u64")]
    eth1_follow_distance: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    target_aggregators_per_committee: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    random_subnets_per_validator: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_random_subnet_subscription: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    seconds_per_eth1_block: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    deposit_chain_id: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    deposit_network_id: u64,
    deposit_contract_address: Address,
}

impl Default for BaseConfig {
    fn default() -> Self {
        let chain_spec = MainnetEthSpec::default_spec();
        BaseConfig::from_chain_spec::<MainnetEthSpec>(&chain_spec)
    }
}

impl BaseConfig {
    /// Maps `self.config_name` to an identifier for an `EthSpec` instance.
    ///
    /// Returns `None` if there is no match.
    pub fn eth_spec_id(&self) -> Option<EthSpecId> {
        Some(match self.config_name.as_str() {
            "mainnet" => EthSpecId::Mainnet,
            "minimal" => EthSpecId::Minimal,
            "toledo" => EthSpecId::Mainnet,
            "prater" => EthSpecId::Mainnet,
            "pyrmont" => EthSpecId::Mainnet,
            _ => return None,
        })
    }

    pub fn from_chain_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        Self {
            config_name: T::spec_name().to_string(),
            // ChainSpec
            max_committees_per_slot: spec.max_committees_per_slot as u64,
            target_committee_size: spec.target_committee_size as u64,
            min_per_epoch_churn_limit: spec.min_per_epoch_churn_limit,
            churn_limit_quotient: spec.churn_limit_quotient,
            shuffle_round_count: spec.shuffle_round_count,
            min_genesis_active_validator_count: spec.min_genesis_active_validator_count,
            min_genesis_time: spec.min_genesis_time,
            genesis_delay: spec.genesis_delay,
            min_deposit_amount: spec.min_deposit_amount,
            max_effective_balance: spec.max_effective_balance,
            ejection_balance: spec.ejection_balance,
            effective_balance_increment: spec.effective_balance_increment,
            hysteresis_quotient: spec.hysteresis_quotient,
            hysteresis_downward_multiplier: spec.hysteresis_downward_multiplier,
            hysteresis_upward_multiplier: spec.hysteresis_upward_multiplier,
            proportional_slashing_multiplier: spec.proportional_slashing_multiplier,
            bls_withdrawal_prefix: spec.bls_withdrawal_prefix_byte,
            seconds_per_slot: spec.seconds_per_slot,
            min_attestation_inclusion_delay: spec.min_attestation_inclusion_delay,
            min_seed_lookahead: spec.min_seed_lookahead.into(),
            max_seed_lookahead: spec.max_seed_lookahead.into(),
            min_validator_withdrawability_delay: spec.min_validator_withdrawability_delay.into(),
            shard_committee_period: spec.shard_committee_period,
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
            max_validators_per_committee: T::MaxValidatorsPerCommittee::to_u32(),
            slots_per_epoch: T::slots_per_epoch(),
            epochs_per_eth1_voting_period: T::EpochsPerEth1VotingPeriod::to_u64(),
            slots_per_historical_root: T::slots_per_historical_root() as u64,
            epochs_per_historical_vector: T::epochs_per_historical_vector() as u64,
            epochs_per_slashings_vector: T::EpochsPerSlashingsVector::to_u64(),
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
            deposit_chain_id: spec.deposit_chain_id,
            deposit_network_id: spec.deposit_network_id,
            deposit_contract_address: spec.deposit_contract_address,
        }
    }

    pub fn from_file(filename: &Path) -> Result<Self, String> {
        let f = File::open(filename)
            .map_err(|e| format!("Error opening spec at {}: {:?}", filename.display(), e))?;
        serde_yaml::from_reader(f)
            .map_err(|e| format!("Error parsing spec at {}: {:?}", filename.display(), e))
    }

    pub fn apply_to_chain_spec<T: EthSpec>(&self, chain_spec: &ChainSpec) -> Option<ChainSpec> {
        // Check that YAML values match type-level EthSpec constants
        if self.max_validators_per_committee != T::MaxValidatorsPerCommittee::to_u32()
            || self.slots_per_epoch != T::slots_per_epoch()
            || self.epochs_per_eth1_voting_period != T::EpochsPerEth1VotingPeriod::to_u64()
            || self.slots_per_historical_root != T::slots_per_historical_root() as u64
            || self.epochs_per_historical_vector != T::epochs_per_historical_vector() as u64
            || self.epochs_per_slashings_vector != T::EpochsPerSlashingsVector::to_u64()
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
            /*
             * Misc
             */
            max_committees_per_slot: self.max_committees_per_slot as usize,
            target_committee_size: self.target_committee_size as usize,
            min_per_epoch_churn_limit: self.min_per_epoch_churn_limit,
            churn_limit_quotient: self.churn_limit_quotient,
            shuffle_round_count: self.shuffle_round_count,
            min_genesis_active_validator_count: self.min_genesis_active_validator_count,
            min_genesis_time: self.min_genesis_time,
            hysteresis_quotient: self.hysteresis_quotient,
            hysteresis_downward_multiplier: self.hysteresis_downward_multiplier,
            hysteresis_upward_multiplier: self.hysteresis_upward_multiplier,
            proportional_slashing_multiplier: self.proportional_slashing_multiplier,
            /*
             * Fork Choice
             */
            safe_slots_to_update_justified: self.safe_slots_to_update_justified,
            /*
             * Validator
             */
            eth1_follow_distance: self.eth1_follow_distance,
            target_aggregators_per_committee: self.target_aggregators_per_committee,
            random_subnets_per_validator: self.random_subnets_per_validator,
            epochs_per_random_subnet_subscription: self.epochs_per_random_subnet_subscription,
            seconds_per_eth1_block: self.seconds_per_eth1_block,
            deposit_chain_id: self.deposit_chain_id,
            deposit_network_id: self.deposit_network_id,
            deposit_contract_address: self.deposit_contract_address,
            /*
             * Gwei values
             */
            min_deposit_amount: self.min_deposit_amount,
            max_effective_balance: self.max_effective_balance,
            ejection_balance: self.ejection_balance,
            effective_balance_increment: self.effective_balance_increment,
            /*
             * Initial values
             */
            genesis_fork_version: self.genesis_fork_version,
            bls_withdrawal_prefix_byte: self.bls_withdrawal_prefix,
            /*
             * Time parameters
             */
            genesis_delay: self.genesis_delay,
            seconds_per_slot: self.seconds_per_slot,
            min_attestation_inclusion_delay: self.min_attestation_inclusion_delay,
            min_seed_lookahead: Epoch::from(self.min_seed_lookahead),
            max_seed_lookahead: Epoch::from(self.max_seed_lookahead),
            min_validator_withdrawability_delay: Epoch::from(
                self.min_validator_withdrawability_delay,
            ),
            shard_committee_period: self.shard_committee_period,
            min_epochs_to_inactivity_penalty: self.min_epochs_to_inactivity_penalty,
            /*
             * Reward and penalty quotients
             */
            base_reward_factor: self.base_reward_factor,
            whistleblower_reward_quotient: self.whistleblower_reward_quotient,
            proposer_reward_quotient: self.proposer_reward_quotient,
            inactivity_penalty_quotient: self.inactivity_penalty_quotient,
            min_slashing_penalty_quotient: self.min_slashing_penalty_quotient,
            /*
             * Signature domains
             */
            domain_beacon_proposer: self.domain_beacon_proposer,
            domain_beacon_attester: self.domain_beacon_attester,
            domain_randao: self.domain_randao,
            domain_deposit: self.domain_deposit,
            domain_voluntary_exit: self.domain_voluntary_exit,
            domain_selection_proof: self.domain_selection_proof,
            domain_aggregate_and_proof: self.domain_aggregate_and_proof,
            /*
             * Altair params (passthrough: they come from the other config file)
             */
            inactivity_penalty_quotient_altair: chain_spec.inactivity_penalty_quotient_altair,
            min_slashing_penalty_quotient_altair: chain_spec.min_slashing_penalty_quotient_altair,
            proportional_slashing_multiplier_altair: chain_spec
                .proportional_slashing_multiplier_altair,
            inactivity_score_bias: chain_spec.inactivity_score_bias,
            epochs_per_sync_committee_period: chain_spec.epochs_per_sync_committee_period,
            domain_sync_committee: chain_spec.domain_sync_committee,
            domain_sync_committee_selection_proof: chain_spec.domain_sync_committee_selection_proof,
            domain_contribution_and_proof: chain_spec.domain_contribution_and_proof,
            altair_fork_version: chain_spec.altair_fork_version,
            altair_fork_slot: chain_spec.altair_fork_slot,
            /*
             * Lighthouse-specific parameters
             *
             * These are paramaters that are present in the chain spec but aren't part of the YAML
             * config. We avoid using `..chain_spec` so that changes to the set of fields don't
             * accidentally get forgotten (explicit better than implicit, yada yada).
             */
            boot_nodes: chain_spec.boot_nodes.clone(),
            network_id: chain_spec.network_id,
            attestation_propagation_slot_range: chain_spec.attestation_propagation_slot_range,
            maximum_gossip_clock_disparity_millis: chain_spec.maximum_gossip_clock_disparity_millis,
            attestation_subnet_count: chain_spec.attestation_subnet_count,
            /*
             * Constants, not configurable.
             */
            genesis_slot: chain_spec.genesis_slot,
            far_future_epoch: chain_spec.far_future_epoch,
            base_rewards_per_epoch: chain_spec.base_rewards_per_epoch,
            deposit_contract_tree_depth: chain_spec.deposit_contract_tree_depth,
        })
    }
}

/// The Altair spec file
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct AltairConfig {
    #[serde(with = "serde_utils::quoted_u64")]
    inactivity_penalty_quotient_altair: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_slashing_penalty_quotient_altair: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    proportional_slashing_multiplier_altair: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    sync_committee_size: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    sync_pubkeys_per_aggregate: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    inactivity_score_bias: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_sync_committee_period: Epoch,
    #[serde(with = "serde_utils::u32_hex")]
    domain_sync_committee: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_sync_committee_selection_proof: u32,
    #[serde(with = "serde_utils::u32_hex")]
    domain_contribution_and_proof: u32,
    #[serde(with = "serde_utils::bytes_4_hex")]
    altair_fork_version: [u8; 4],
    altair_fork_slot: Option<MaybeQuoted<Slot>>,
    // FIXME(altair): sync protocol params?
}

impl AltairConfig {
    pub fn from_file(filename: &Path) -> Result<Self, String> {
        let f = File::open(filename)
            .map_err(|e| format!("Error opening spec at {}: {:?}", filename.display(), e))?;
        serde_yaml::from_reader(f)
            .map_err(|e| format!("Error parsing spec at {}: {:?}", filename.display(), e))
    }

    pub fn apply_to_chain_spec<T: EthSpec>(&self, chain_spec: &ChainSpec) -> Option<ChainSpec> {
        // Pattern-match to avoid missing any fields.
        let &AltairConfig {
            inactivity_penalty_quotient_altair,
            min_slashing_penalty_quotient_altair,
            proportional_slashing_multiplier_altair,
            sync_committee_size,
            sync_pubkeys_per_aggregate,
            inactivity_score_bias,
            epochs_per_sync_committee_period,
            domain_sync_committee,
            domain_sync_committee_selection_proof,
            domain_contribution_and_proof,
            altair_fork_version,
            altair_fork_slot,
        } = self;

        if sync_committee_size != T::SyncCommitteeSize::to_u64()
            || sync_pubkeys_per_aggregate != T::SyncPubkeysPerAggregate::to_u64()
        {
            return None;
        }

        Some(ChainSpec {
            inactivity_penalty_quotient_altair,
            min_slashing_penalty_quotient_altair,
            proportional_slashing_multiplier_altair,
            inactivity_score_bias,
            epochs_per_sync_committee_period,
            domain_sync_committee,
            domain_sync_committee_selection_proof,
            domain_contribution_and_proof,
            altair_fork_version,
            altair_fork_slot: altair_fork_slot.map(|q| q.value),
            ..chain_spec.clone()
        })
    }

    pub fn from_chain_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        Self {
            inactivity_penalty_quotient_altair: spec.inactivity_penalty_quotient_altair,
            min_slashing_penalty_quotient_altair: spec.min_slashing_penalty_quotient_altair,
            proportional_slashing_multiplier_altair: spec.proportional_slashing_multiplier_altair,
            sync_committee_size: T::SyncCommitteeSize::to_u64(),
            sync_pubkeys_per_aggregate: T::SyncPubkeysPerAggregate::to_u64(),
            inactivity_score_bias: spec.inactivity_score_bias,
            epochs_per_sync_committee_period: spec.epochs_per_sync_committee_period,
            domain_sync_committee: spec.domain_sync_committee,
            domain_sync_committee_selection_proof: spec.domain_sync_committee_selection_proof,
            domain_contribution_and_proof: spec.domain_contribution_and_proof,
            altair_fork_version: spec.altair_fork_version,
            altair_fork_slot: spec
                .altair_fork_slot
                .map(|slot| MaybeQuoted { value: slot }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_mainnet_spec_can_be_constructed() {
        let _ = ChainSpec::mainnet();
    }

    #[allow(clippy::useless_vec)]
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
        test_domain(Domain::SyncCommittee, spec.domain_sync_committee, &spec);
    }

    #[test]
    fn decode_no_altair() {
        let spec = MainnetEthSpec::default_spec();
        let base_config = BaseConfig::from_chain_spec::<MainnetEthSpec>(&spec);

        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let f = File::create(tmp_file.as_ref()).unwrap();
        serde_yaml::to_writer(f, &base_config).expect("failed to write or serialize");

        let f = File::open(tmp_file.as_ref()).unwrap();
        let standard_config: StandardConfig = serde_yaml::from_reader(f).unwrap();

        let standard_base = standard_config.as_base().unwrap();
        assert_eq!(standard_base.base, base_config);
        assert!(standard_base.extra_fields.is_empty());
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

        let yamlconfig = BaseConfig::from_chain_spec::<MinimalEthSpec>(&minimal_spec);
        // write fresh minimal config to file
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        // deserialize minimal config from file
        let from: BaseConfig = serde_yaml::from_reader(reader).expect("error while deserializing");
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
        let yamlconfig = BaseConfig::from_chain_spec::<MainnetEthSpec>(&mainnet_spec);
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: BaseConfig = serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn extra_fields_round_trip() {
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let mainnet_spec = ChainSpec::mainnet();
        let mut yamlconfig = StandardConfig::from_chain_spec::<MainnetEthSpec>(&mainnet_spec);
        let (k1, v1) = ("SAMPLE_HARDFORK_KEY1", "123456789");
        let (k2, v2) = ("SAMPLE_HARDFORK_KEY2", "987654321");
        yamlconfig.extra_fields_mut().insert(k1.into(), v1.into());
        yamlconfig.extra_fields_mut().insert(k2.into(), v2.into());
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: StandardConfig =
            serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn apply_to_spec() {
        let mut spec = ChainSpec::minimal();
        let yamlconfig = BaseConfig::from_chain_spec::<MinimalEthSpec>(&spec);

        // modifying the original spec
        spec.max_committees_per_slot += 1;
        spec.deposit_chain_id += 1;
        spec.deposit_network_id += 1;
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
