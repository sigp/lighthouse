use std::{fs::File, path::Path, time::Duration};

use educe::Educe;
use ethereum_hashing::hash;
use fixed_bytes::FixedBytesExtended;
use int_to_bytes::int_to_bytes4;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_utils::quoted_u64::MaybeQuoted;
use ssz::Encode;
use ssz_types::RuntimeVariableList;
use tracing::error;
use tree_hash::TreeHash;

use crate::{
    consts::bellatrix::BASIS_POINTS,
    core::{
        APPLICATION_DOMAIN_BUILDER, Address, ApplicationDomain, EnrForkId, Epoch, EthSpec,
        EthSpecId, ExecutionBlockHash, Hash256, MainnetEthSpec, Slot, Uint256,
    },
    fork::{Fork, ForkData, ForkName},
};

/// Each of the BLS signature domains.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Domain {
    BlsToExecutionChange,
    BeaconProposer,
    BeaconAttester,
    Randao,
    Deposit,
    VoluntaryExit,
    SelectionProof,
    AggregateAndProof,
    SyncCommittee,
    ContributionAndProof,
    SyncCommitteeSelectionProof,
    BeaconBuilder,
    PTCAttester,
    ProposerPreferences,
    BuilderDeposit,
    InclusionListCommittee,
    ExecutionProof,
    ApplicationMask(ApplicationDomain),
}

/// Lighthouse's internal configuration struct.
///
/// Contains a mixture of "preset" and "config" values w.r.t to the EF definitions.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Debug, Clone)]
pub struct ChainSpec {
    /*
     * Config name
     */
    pub config_name: Option<String>,

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
    pub max_per_epoch_activation_churn_limit: u64,
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
    pub eth1_address_withdrawal_prefix_byte: u8,
    pub compounding_withdrawal_prefix_byte: u8,
    pub builder_withdrawal_prefix_byte: u8,

    /*
     * Time parameters
     */
    pub genesis_delay: u64,
    seconds_per_slot: u64,
    // Private so that this value can't get changed except via the `set_slot_duration_ms` function.
    slot_duration_ms: u64,
    pub slot_duration_ms_heze: u64,
    pub min_attestation_inclusion_delay: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_epochs_to_inactivity_penalty: u64,
    pub min_validator_withdrawability_delay: Epoch,
    pub shard_committee_period: u64,
    pub proposer_reorg_cutoff_bps: u64,
    pub attestation_due_bps: u64,
    pub attestation_due_bps_gloas: u64,
    pub payload_due_bps: u64,
    pub payload_attestation_due_bps: u64,
    pub aggregate_due_bps: u64,
    pub aggregate_due_bps_gloas: u64,
    pub sync_message_due_bps: u64,
    pub sync_message_due_bps_gloas: u64,
    pub contribution_due_bps: u64,
    pub contribution_due_bps_gloas: u64,
    pub inclusion_list_due_bps: u64,

    /*
     * Derived time values (computed at startup via `compute_derived_values()`)
     */
    slot_component_durations: Vec<SlotComponentDurations>,

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
    pub(crate) domain_beacon_proposer: u32,
    pub(crate) domain_beacon_attester: u32,
    pub(crate) domain_randao: u32,
    pub(crate) domain_deposit: u32,
    pub(crate) domain_voluntary_exit: u32,
    pub(crate) domain_selection_proof: u32,
    pub(crate) domain_aggregate_and_proof: u32,
    pub(crate) domain_beacon_builder: u32,
    pub(crate) domain_ptc_attester: u32,
    pub(crate) domain_proposer_preferences: u32,
    pub(crate) domain_builder_deposit: u32,
    pub(crate) domain_inclusion_list_committee: u32,
    pub(crate) domain_execution_proof: u32,

    /*
     * Fork choice
     */
    pub proposer_score_boost: u64,
    pub reorg_head_weight_threshold: u64,
    pub reorg_parent_weight_threshold: u64,
    pub reorg_max_epochs_since_finalization: u64,

    /*
     * Fast confirmation rule
     */
    /// Maximum assumed percentage of Byzantine validators (0-25).
    pub confirmation_byzantine_threshold: u64,

    /*
     * Eth1
     */
    pub eth1_follow_distance: u64,
    pub seconds_per_eth1_block: u64,
    pub deposit_chain_id: u64,
    pub deposit_network_id: u64,
    pub deposit_contract_address: Address,

    /*
     * Execution Specs
     */
    pub gas_limit_adjustment_factor: u64,

    /*
     * Altair hard fork params
     */
    pub inactivity_penalty_quotient_altair: u64,
    pub min_slashing_penalty_quotient_altair: u64,
    pub proportional_slashing_multiplier_altair: u64,
    pub epochs_per_sync_committee_period: Epoch,
    pub inactivity_score_bias: u64,
    pub inactivity_score_recovery_rate: u64,
    pub min_sync_committee_participants: u64,
    pub update_timeout: u64,
    pub(crate) domain_sync_committee: u32,
    pub(crate) domain_sync_committee_selection_proof: u32,
    pub(crate) domain_contribution_and_proof: u32,
    pub altair_fork_version: [u8; 4],
    /// The Altair fork epoch is optional, with `None` representing "Altair never happens".
    pub altair_fork_epoch: Option<Epoch>,

    /*
     * Bellatrix hard fork params
     */
    pub inactivity_penalty_quotient_bellatrix: u64,
    pub min_slashing_penalty_quotient_bellatrix: u64,
    pub proportional_slashing_multiplier_bellatrix: u64,
    pub bellatrix_fork_version: [u8; 4],
    /// The Bellatrix fork epoch is optional, with `None` representing "Bellatrix never happens".
    pub bellatrix_fork_epoch: Option<Epoch>,
    pub terminal_total_difficulty: Uint256,
    pub terminal_block_hash: ExecutionBlockHash,
    pub terminal_block_hash_activation_epoch: Epoch,

    /*
     * Capella hard fork params
     */
    pub capella_fork_version: [u8; 4],
    /// The Capella fork epoch is optional, with `None` representing "Capella never happens".
    pub capella_fork_epoch: Option<Epoch>,
    pub max_validators_per_withdrawals_sweep: u64,

    /*
     * Deneb hard fork params
     */
    pub deneb_fork_version: [u8; 4],
    pub deneb_fork_epoch: Option<Epoch>,

    /*
     * Electra hard fork params
     */
    pub electra_fork_version: [u8; 4],
    /// The Electra fork epoch is optional, with `None` representing "Electra never happens".
    pub electra_fork_epoch: Option<Epoch>,
    pub unset_deposit_requests_start_index: u64,
    pub full_exit_request_amount: u64,
    pub min_activation_balance: u64,
    pub max_effective_balance_electra: u64,
    pub min_slashing_penalty_quotient_electra: u64,
    pub whistleblower_reward_quotient_electra: u64,
    pub max_pending_partials_per_withdrawals_sweep: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub max_per_epoch_activation_exit_churn_limit: u64,

    /*
     * Fulu hard fork params
     */
    pub fulu_fork_version: [u8; 4],
    /// The Fulu fork epoch is optional, with `None` representing "Fulu never happens".
    pub fulu_fork_epoch: Option<Epoch>,
    pub number_of_custody_groups: u64,
    pub data_column_sidecar_subnet_count: u64,
    pub samples_per_slot: u64,
    pub custody_requirement: u64,
    pub validator_custody_requirement: u64,
    pub balance_per_additional_custody_group: u64,

    /*
     * Gloas hard fork params
     */
    pub gloas_fork_version: [u8; 4],
    /// The Gloas fork epoch is optional, with `None` representing "Gloas never happens".
    pub gloas_fork_epoch: Option<Epoch>,
    pub builder_payment_threshold_numerator: u64,
    pub builder_payment_threshold_denominator: u64,
    pub min_builder_withdrawability_delay: Epoch,
    pub churn_limit_quotient_gloas: u64,
    pub consolidation_churn_limit_quotient: u64,
    pub max_per_epoch_activation_churn_limit_gloas: u64,
    pub gas_limit_schedule: GasLimitSchedule,

    /*
     * Heze hard fork params
     */
    pub heze_fork_version: [u8; 4],
    /// The Heze fork epoch is optional, with `None` representing "Heze never happens".
    pub heze_fork_epoch: Option<Epoch>,

    /*
     * Networking
     */
    pub boot_nodes: Vec<String>,
    pub network_id: u8,
    pub target_aggregators_per_committee: u64,
    pub max_payload_size: u64,
    max_request_blocks: u64,
    pub min_epochs_for_block_requests: u64,
    pub ttfb_timeout: u64,
    pub resp_timeout: u64,
    pub attestation_propagation_slot_range: u64,
    pub maximum_gossip_clock_disparity: u64,
    pub message_domain_invalid_snappy: [u8; 4],
    pub message_domain_valid_snappy: [u8; 4],
    pub subnets_per_node: u8,
    pub epochs_per_subnet_subscription: u64,
    pub attestation_subnet_count: u64,
    pub attestation_subnet_extra_bits: u8,
    pub attestation_subnet_prefix_bits: u8,

    /*
     * Networking Deneb
     */
    max_request_blocks_deneb: u64,
    max_request_blob_sidecars: u64,
    pub max_request_data_column_sidecars: u64,
    pub min_epochs_for_blob_sidecars_requests: u64,
    blob_sidecar_subnet_count: u64,
    max_blobs_per_block: u64,

    /*
     * Networking Electra
     */
    max_blobs_per_block_electra: u64,
    blob_sidecar_subnet_count_electra: u64,
    max_request_blob_sidecars_electra: u64,

    /*
     * Networking Fulu
     */
    pub blob_schedule: BlobSchedule,
    pub min_epochs_for_data_column_sidecars_requests: u64,
    pub min_blob_data_retention_ms: u64,

    /*
     * Networking Gloas
     */
    pub max_request_payloads: u64,

    /*
     * Networking Heze
     */
    pub max_transactions_bytes_per_inclusion_list: u64,
    pub max_request_inclusion_list: u64,
    pub min_slots_for_inclusion_lists_requests: u64,

    /*
     * Networking Derived
     *
     * When adding fields here, make sure any values are derived again during `apply_to_chain_spec`.
     */
    pub max_blocks_by_root_request: usize,
    pub max_blocks_by_root_request_deneb: usize,
    pub max_blobs_by_root_request: usize,
    pub max_data_columns_by_root_request: usize,
    pub max_payload_envelopes_by_root_request: usize,

    /*
     * Application params
     */
    pub(crate) domain_application_mask: u32,

    /*
     * Capella params
     */
    pub(crate) domain_bls_to_execution_change: u32,
}

impl ChainSpec {
    /// Construct a `ChainSpec` from a standard config.
    pub fn from_config<E: EthSpec>(config: &Config) -> Option<Self> {
        let spec = E::default_spec();
        config.apply_to_chain_spec::<E>(&spec)
    }

    /// Returns an `EnrForkId` for the given `slot`.
    pub fn enr_fork_id<E: EthSpec>(
        &self,
        slot: Slot,
        genesis_validators_root: Hash256,
    ) -> EnrForkId {
        EnrForkId {
            fork_digest: self
                .compute_fork_digest(genesis_validators_root, slot.epoch(E::slots_per_epoch())),
            next_fork_version: self.next_fork_version::<E>(slot),
            next_fork_epoch: self
                .next_digest_epoch(slot.epoch(E::slots_per_epoch()))
                .unwrap_or(self.far_future_epoch),
        }
    }

    /// Returns the `next_fork_version`.
    ///
    /// This is the fork version in effect at the next digest epoch. BPO forks do not change the
    /// fork version, so a BPO fork scheduled before the next regular fork keeps the current one.
    /// `next_fork_version = current_fork_version` if no future fork is planned.
    pub fn next_fork_version<E: EthSpec>(&self, slot: Slot) -> [u8; 4] {
        let current_epoch = slot.epoch(E::slots_per_epoch());
        let next_fork_epoch = match self.next_digest_epoch(current_epoch) {
            Some(epoch) if epoch != self.far_future_epoch => epoch,
            _ => current_epoch,
        };
        self.fork_version_for_name(self.fork_name_at_epoch(next_fork_epoch))
    }

    /// Returns the epoch of the next scheduled fork along with its corresponding `ForkName`.
    ///
    /// If no future forks are scheduled, this function returns `None`.
    pub fn next_fork_epoch<E: EthSpec>(&self, slot: Slot) -> Option<(ForkName, Epoch)> {
        let current_fork_name = self.fork_name_at_slot::<E>(slot);
        let next_fork_name = current_fork_name.next_fork()?;
        let fork_epoch = self.fork_epoch(next_fork_name)?;
        Some((next_fork_name, fork_epoch))
    }

    /// Returns the name of the fork which is active at `slot`.
    pub fn fork_name_at_slot<E: EthSpec>(&self, slot: Slot) -> ForkName {
        self.fork_name_at_epoch(slot.epoch(E::slots_per_epoch()))
    }

    /// Returns the name of the fork which is active at `epoch`.
    pub fn fork_name_at_epoch(&self, epoch: Epoch) -> ForkName {
        let forks = [
            (self.heze_fork_epoch, ForkName::Heze),
            (self.gloas_fork_epoch, ForkName::Gloas),
            (self.fulu_fork_epoch, ForkName::Fulu),
            (self.electra_fork_epoch, ForkName::Electra),
            (self.deneb_fork_epoch, ForkName::Deneb),
            (self.capella_fork_epoch, ForkName::Capella),
            (self.bellatrix_fork_epoch, ForkName::Bellatrix),
            (self.altair_fork_epoch, ForkName::Altair),
        ];

        // Find the first fork where `epoch` is >= `fork_epoch`.
        for (fork_epoch_opt, fork_name) in forks.iter() {
            if let Some(fork_epoch) = fork_epoch_opt
                && epoch >= *fork_epoch
            {
                return *fork_name;
            }
        }

        ForkName::Base
    }

    /// Returns the fork version for a named fork.
    pub fn fork_version_for_name(&self, fork_name: ForkName) -> [u8; 4] {
        match fork_name {
            ForkName::Base => self.genesis_fork_version,
            ForkName::Altair => self.altair_fork_version,
            ForkName::Bellatrix => self.bellatrix_fork_version,
            ForkName::Capella => self.capella_fork_version,
            ForkName::Deneb => self.deneb_fork_version,
            ForkName::Electra => self.electra_fork_version,
            ForkName::Fulu => self.fulu_fork_version,
            ForkName::Gloas => self.gloas_fork_version,
            ForkName::Heze => self.heze_fork_version,
        }
    }

    // This is `compute_fork_version` in the spec
    pub fn fork_version_for_epoch(&self, epoch: Epoch) -> [u8; 4] {
        self.fork_version_for_name(self.fork_name_at_epoch(epoch))
    }

    /// For a given fork name, return the epoch at which it activates.
    pub fn fork_epoch(&self, fork_name: ForkName) -> Option<Epoch> {
        match fork_name {
            ForkName::Base => Some(Epoch::new(0)),
            ForkName::Altair => self.altair_fork_epoch,
            ForkName::Bellatrix => self.bellatrix_fork_epoch,
            ForkName::Capella => self.capella_fork_epoch,
            ForkName::Deneb => self.deneb_fork_epoch,
            ForkName::Electra => self.electra_fork_epoch,
            ForkName::Fulu => self.fulu_fork_epoch,
            ForkName::Gloas => self.gloas_fork_epoch,
            ForkName::Heze => self.heze_fork_epoch,
        }
    }

    pub fn inactivity_penalty_quotient_for_fork(&self, fork_name: ForkName) -> u64 {
        if fork_name >= ForkName::Bellatrix {
            self.inactivity_penalty_quotient_bellatrix
        } else if fork_name >= ForkName::Altair {
            self.inactivity_penalty_quotient_altair
        } else {
            self.inactivity_penalty_quotient
        }
    }

    pub fn max_effective_balance_for_fork(&self, fork_name: ForkName) -> u64 {
        if fork_name.electra_enabled() {
            self.max_effective_balance_electra
        } else {
            self.max_effective_balance
        }
    }

    /// Returns true if the given epoch is greater than or equal to the `FULU_FORK_EPOCH`.
    pub fn is_peer_das_enabled_for_epoch(&self, block_epoch: Epoch) -> bool {
        self.fulu_fork_epoch
            .is_some_and(|fulu_fork_epoch| block_epoch >= fulu_fork_epoch)
    }

    /// Returns true if PeerDAS is scheduled. Alias for [`Self::is_fulu_scheduled`]
    pub fn is_peer_das_scheduled(&self) -> bool {
        self.is_fulu_scheduled()
    }

    /// Returns true if `FULU_FORK_EPOCH` is set and is not set to `FAR_FUTURE_EPOCH`.
    pub fn is_fulu_scheduled(&self) -> bool {
        self.fulu_fork_epoch
            .is_some_and(|fulu_fork_epoch| fulu_fork_epoch != self.far_future_epoch)
    }

    /// Returns true if `GLOAS_FORK_EPOCH` is set and is not set to `FAR_FUTURE_EPOCH`.
    pub fn is_gloas_scheduled(&self) -> bool {
        self.gloas_fork_epoch
            .is_some_and(|gloas_fork_epoch| gloas_fork_epoch != self.far_future_epoch)
    }

    /// Returns true if `HEZE_FORK_EPOCH` is set and is not set to `FAR_FUTURE_EPOCH`.
    pub fn is_heze_scheduled(&self) -> bool {
        self.heze_fork_epoch
            .is_some_and(|heze_fork_epoch| heze_fork_epoch != self.far_future_epoch)
    }

    /// Returns a full `Fork` struct for a given epoch.
    pub fn fork_at_epoch(&self, epoch: Epoch) -> Fork {
        let current_fork_name = self.fork_name_at_epoch(epoch);

        let fork_epoch = self
            .fork_epoch(current_fork_name)
            .unwrap_or_else(|| Epoch::new(0));

        // At genesis the Fork is initialised with two copies of the same value for both
        // `previous_version` and `current_version` (see `initialize_beacon_state_from_eth1`).
        let previous_fork_name = if fork_epoch == 0 {
            current_fork_name
        } else {
            current_fork_name.previous_fork().unwrap_or(ForkName::Base)
        };

        Fork {
            previous_version: self.fork_version_for_name(previous_fork_name),
            current_version: self.fork_version_for_name(current_fork_name),
            epoch: fork_epoch,
        }
    }

    /// Returns a full `Fork` struct for a given `ForkName` or `None` if the fork does not yet have
    /// an activation epoch.
    pub fn fork_for_name(&self, fork_name: ForkName) -> Option<Fork> {
        let previous_fork_name = fork_name.previous_fork().unwrap_or(ForkName::Base);
        let epoch = self.fork_epoch(fork_name)?;

        Some(Fork {
            previous_version: self.fork_version_for_name(previous_fork_name),
            current_version: self.fork_version_for_name(fork_name),
            epoch,
        })
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
            Domain::BeaconBuilder => self.domain_beacon_builder,
            Domain::PTCAttester => self.domain_ptc_attester,
            Domain::ProposerPreferences => self.domain_proposer_preferences,
            Domain::BuilderDeposit => self.domain_builder_deposit,
            Domain::InclusionListCommittee => self.domain_inclusion_list_committee,
            Domain::ExecutionProof => self.domain_execution_proof,
            Domain::SyncCommittee => self.domain_sync_committee,
            Domain::ContributionAndProof => self.domain_contribution_and_proof,
            Domain::SyncCommitteeSelectionProof => self.domain_sync_committee_selection_proof,
            Domain::ApplicationMask(application_domain) => application_domain.get_domain_constant(),
            Domain::BlsToExecutionChange => self.domain_bls_to_execution_change,
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

    // This should be updated to include the current fork and the genesis validators root, but discussion is ongoing:
    //
    // https://github.com/ethereum/builder-specs/issues/14
    //
    // NOTE: This domain is only used for out-of-protocol block building, DO NOT use it for Gloas/ePBS.
    pub fn get_builder_application_domain(&self) -> Hash256 {
        self.compute_domain(
            Domain::ApplicationMask(ApplicationDomain::Builder),
            self.genesis_fork_version,
            Hash256::zero(),
        )
    }

    /// The signing domain for a Gloas builder-API `SignedRequestAuth`.
    ///
    /// Per builder-specs #165 this is `compute_domain(DOMAIN_REQUEST_AUTH)`: the genesis fork version
    /// and a zero genesis-validators-root, matching `get_builder_application_domain`'s out-of-protocol
    /// computation but with the `DOMAIN_REQUEST_AUTH` (0x0B000001) domain type.
    pub fn get_request_auth_domain(&self) -> Hash256 {
        self.compute_domain(
            Domain::ApplicationMask(ApplicationDomain::RequestAuth),
            self.genesis_fork_version,
            Hash256::zero(),
        )
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
    pub fn compute_fork_digest(&self, genesis_validators_root: Hash256, epoch: Epoch) -> [u8; 4] {
        let fork_version = self.fork_version_for_epoch(epoch);
        let mut base_digest = [0u8; 4];
        let root = Self::compute_fork_data_root(fork_version, genesis_validators_root);
        base_digest.copy_from_slice(
            root.as_slice()
                .get(0..4)
                .expect("root hash is at least 4 bytes"),
        );

        let Some(blob_parameters) = self.get_blob_parameters(epoch) else {
            return base_digest;
        };

        match self.fulu_fork_epoch {
            Some(fulu_epoch) if epoch >= fulu_epoch => {
                // Concatenate epoch and max_blobs_per_block as u64 bytes
                let mut input = Vec::with_capacity(16);
                input.extend_from_slice(&blob_parameters.epoch.as_u64().to_le_bytes());
                input.extend_from_slice(&blob_parameters.max_blobs_per_block.to_le_bytes());

                // Hash the concatenated bytes
                let hash = hash(&input);

                // XOR the base digest with the first 4 bytes of the hash
                let mut masked_digest = [0u8; 4];
                for (i, (a, b)) in base_digest.iter().zip(hash.iter()).enumerate() {
                    if let Some(x) = masked_digest.get_mut(i) {
                        *x = a ^ b;
                    }
                }
                masked_digest
            }
            _ => base_digest,
        }
    }

    pub fn all_digest_epochs(&self) -> impl std::iter::Iterator<Item = Epoch> {
        let mut relevant_epochs = ForkName::list_all_fork_epochs(self)
            .into_iter()
            .filter_map(|(_, epoch)| epoch)
            .collect::<std::collections::HashSet<_>>();

        if self.is_fulu_scheduled() {
            for blob_parameters in &self.blob_schedule {
                relevant_epochs.insert(blob_parameters.epoch);
            }
        }
        let mut vec = relevant_epochs.into_iter().collect::<Vec<_>>();
        vec.sort();
        vec.into_iter()
    }

    pub fn next_digest_epoch(&self, epoch: Epoch) -> Option<Epoch> {
        match self.fulu_fork_epoch {
            Some(fulu_epoch) if epoch >= fulu_epoch => self
                .all_digest_epochs()
                .find(|digest_epoch| *digest_epoch > epoch),
            _ => self
                .fork_name_at_epoch(epoch)
                .next_fork()
                .and_then(|fork_name| self.fork_epoch(fork_name)),
        }
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
                .as_slice()
                .get(..28)
                .expect("fork has is 32 bytes so first 28 bytes should exist"),
        );

        Hash256::from(domain)
    }

    /// Compute the epoch used for activations prior to Deneb, and for exits under all forks.
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
    pub fn compute_activation_exit_epoch(&self, epoch: Epoch) -> Result<Epoch, ArithError> {
        epoch.safe_add(1)?.safe_add(self.max_seed_lookahead)
    }

    pub fn maximum_gossip_clock_disparity(&self) -> Duration {
        Duration::from_millis(self.maximum_gossip_clock_disparity)
    }

    pub fn ttfb_timeout(&self) -> Duration {
        Duration::from_secs(self.ttfb_timeout)
    }

    pub fn resp_timeout(&self) -> Duration {
        Duration::from_secs(self.resp_timeout)
    }

    pub fn max_blocks_by_root_request(&self, fork_name: ForkName) -> usize {
        if fork_name >= ForkName::Deneb {
            self.max_blocks_by_root_request_deneb
        } else {
            self.max_blocks_by_root_request
        }
    }

    pub fn max_request_blocks(&self, fork_name: ForkName) -> usize {
        if fork_name >= ForkName::Deneb {
            self.max_request_blocks_deneb as usize
        } else {
            self.max_request_blocks as usize
        }
    }

    pub fn max_request_payloads(&self) -> usize {
        self.max_request_payloads as usize
    }

    pub fn max_request_blob_sidecars(&self, fork_name: ForkName) -> usize {
        if fork_name.electra_enabled() {
            self.max_request_blob_sidecars_electra as usize
        } else {
            self.max_request_blob_sidecars as usize
        }
    }

    /// Returns the highest possible value for max_request_blobs based on enabled forks.
    ///
    /// This is useful for upper bounds in testing.
    pub fn max_request_blobs_upper_bound(&self) -> usize {
        if self.electra_fork_epoch.is_some() {
            self.max_request_blob_sidecars_electra as usize
        } else {
            self.max_request_blob_sidecars as usize
        }
    }

    /// Return the value of `MAX_BLOBS_PER_BLOCK` for the given `epoch`.
    /// NOTE: this function is *technically* not spec compliant, but
    /// I'm told this is what the other clients are doing for `devnet-0`..
    pub fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        match self.fulu_fork_epoch {
            Some(fulu_epoch) if epoch >= fulu_epoch => self
                .blob_schedule
                .max_blobs_for_epoch(epoch)
                .unwrap_or(self.max_blobs_per_block_electra),
            _ => match self.electra_fork_epoch {
                Some(electra_epoch) if epoch >= electra_epoch => self.max_blobs_per_block_electra,
                _ => self.max_blobs_per_block,
            },
        }
    }

    /// Return the blob parameters at a given epoch.
    fn get_blob_parameters(&self, epoch: Epoch) -> Option<BlobParameters> {
        match self.fulu_fork_epoch {
            Some(fulu_epoch) if epoch >= fulu_epoch => self
                .blob_schedule
                .blob_parameters_for_epoch(epoch)
                .or_else(|| {
                    Some(BlobParameters {
                        epoch: self
                            .electra_fork_epoch
                            .expect("electra fork epoch must be set if fulu epoch is set"),
                        max_blobs_per_block: self.max_blobs_per_block_electra,
                    })
                }),
            _ => None,
        }
    }

    /// Return the scheduled gas limit at the given epoch, per EIP-8261.
    ///
    /// The schedule only applies from the Gloas fork onwards.
    pub fn get_scheduled_gas_limit(&self, epoch: Epoch) -> Option<u64> {
        match self.gloas_fork_epoch {
            Some(gloas_epoch) if epoch >= gloas_epoch => {
                self.gas_limit_schedule.gas_limit_for_epoch(epoch)
            }
            _ => None,
        }
    }

    /// The gas limit to target at `epoch` when the operator has not configured one.
    ///
    /// From the Gloas fork this is the scheduled gas limit (EIP-8261). Before the fork, and on a
    /// network whose schedule has no entry for `epoch`, it is `DEFAULT_GAS_LIMIT`.
    pub fn default_gas_limit(&self, epoch: Epoch) -> u64 {
        self.get_scheduled_gas_limit(epoch)
            .unwrap_or(DEFAULT_GAS_LIMIT)
    }

    // TODO(EIP-7892): remove this once we have fork-version changes on BPO forks
    pub fn max_blobs_per_block_within_fork(&self, fork_name: ForkName) -> u64 {
        if !fork_name.fulu_enabled() {
            if fork_name.electra_enabled() {
                self.max_blobs_per_block_electra
            } else {
                self.max_blobs_per_block
            }
        } else {
            // Find the max blobs per block in the fork schedule
            // This logic will need to be more complex once there are forks beyond Fulu
            let mut max_blobs_per_block = self.max_blobs_per_block_electra;
            for entry in &self.blob_schedule {
                if entry.max_blobs_per_block > max_blobs_per_block {
                    max_blobs_per_block = entry.max_blobs_per_block;
                }
            }
            max_blobs_per_block
        }
    }

    /// Gloas sidecar bounds use the largest blob limit in the entire schedule.
    pub fn compute_max_data_column_sidecar_size_gloas<E: EthSpec>(&self) -> usize {
        crate::DataColumnSidecarGloas::<E>::max_size(
            self.max_blobs_per_block_within_fork(ForkName::Gloas) as usize,
        )
    }

    pub fn compute_max_partial_data_column_sidecar_size_gloas<E: EthSpec>(&self) -> usize {
        crate::PartialDataColumnSidecarGloas::<E>::max_size(
            self.max_blobs_per_block_within_fork(ForkName::Gloas) as usize,
        )
    }

    /// Returns the `BLOB_SIDECAR_SUBNET_COUNT` at the given fork_name.
    pub fn blob_sidecar_subnet_count(&self, fork_name: ForkName) -> u64 {
        if fork_name.electra_enabled() {
            self.blob_sidecar_subnet_count_electra
        } else {
            self.blob_sidecar_subnet_count
        }
    }

    /// Returns the highest possible value of blob sidecar subnet count based on enabled forks.
    ///
    /// This is useful for upper bounds for the subnet count during a given run of lighthouse.
    pub fn blob_sidecar_subnet_count_max(&self) -> u64 {
        if self.electra_fork_epoch.is_some() {
            self.blob_sidecar_subnet_count_electra
        } else {
            self.blob_sidecar_subnet_count
        }
    }

    /// Returns the number of data columns per custody group.
    pub fn data_columns_per_group<E: EthSpec>(&self) -> u64 {
        (E::number_of_columns() as u64)
            .safe_div(self.number_of_custody_groups)
            .expect("Custody group count must be greater than 0")
    }

    /// Returns the number of column sidecars to sample per slot.
    pub fn sampling_size_columns<E: EthSpec>(
        &self,
        custody_group_count: u64,
    ) -> Result<usize, String> {
        let sampling_size_groups = self.sampling_size_custody_groups(custody_group_count)?;
        let columns_per_custody_group = self.data_columns_per_group::<E>();

        let sampling_size_columns = columns_per_custody_group
            .safe_mul(sampling_size_groups)
            .map_err(|_| "Computing sampling size should not overflow")?;

        Ok(sampling_size_columns as usize)
    }

    /// Returns the number of custody groups to sample per slot.
    pub fn sampling_size_custody_groups(&self, custody_group_count: u64) -> Result<u64, String> {
        Ok(std::cmp::max(custody_group_count, self.samples_per_slot))
    }

    /// Returns the min epoch for blob / data column sidecar requests based on the current epoch.
    /// Switch to use the column sidecar config once the `blob_retention_epoch` has passed Fulu fork epoch.
    /// Never uses the `blob_retention_epoch` for networks that started with Fulu enabled.
    pub fn min_epoch_data_availability_boundary<E: EthSpec>(
        &self,
        current_epoch: Epoch,
    ) -> Option<Epoch> {
        let deneb_fork_epoch = self.deneb_fork_epoch?;
        let blob_retention_epoch =
            current_epoch.saturating_sub(self.min_epochs_for_blob_sidecars_requests);
        let data_column_retention_epoch =
            current_epoch.saturating_sub(self.min_epochs_for_data_column_sidecars_requests);
        if let Some(fulu_fork_epoch) = self.fulu_fork_epoch
            && blob_retention_epoch >= fulu_fork_epoch
        {
            // EIP-8198 activates at the Heze fork.
            if self.fork_name_at_epoch(current_epoch).heze_enabled() {
                Some(std::cmp::max(
                    fulu_fork_epoch,
                    self.compute_blob_data_retention_start_epoch::<E>(current_epoch)
                        .unwrap_or(data_column_retention_epoch),
                ))
            } else {
                Some(data_column_retention_epoch)
            }
        } else {
            Some(std::cmp::max(deneb_fork_epoch, blob_retention_epoch))
        }
    }

    /// Worst-case compressed length for a given payload of size n when using snappy.
    ///
    /// https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/snappy.cc#L218C1-L218C47
    /// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#max_compressed_len
    fn max_compressed_len_snappy(n: usize) -> Option<usize> {
        32_usize.checked_add(n)?.checked_add(n / 6)
    }

    /// Max compressed length of a message that we receive over gossip.
    pub fn max_compressed_len(&self) -> usize {
        Self::max_compressed_len_snappy(self.max_payload_size as usize)
            .expect("should not overflow")
    }

    /// Max allowed size of a raw, compressed message received over the network.
    ///
    /// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#max_compressed_len
    pub fn max_message_size(&self) -> usize {
        std::cmp::max(
            // 1024 to account for framing + encoding overhead
            Self::max_compressed_len_snappy(self.max_payload_size as usize)
                .expect("should not overflow")
                .safe_add(1024)
                .expect("should not overflow"),
            //1MB
            1024 * 1024,
        )
    }

    /// Spec: `get_attestation_due_ms`. Returns the epoch-appropriate threshold.
    pub fn get_attestation_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        let durations = self.slot_component_durations_at::<E>(slot);
        if self.fork_name_at_slot::<E>(slot).gloas_enabled() {
            durations.attestation_due_gloas
        } else {
            durations.attestation_due
        }
    }

    /// Spec: `get_payload_due_ms`.
    pub fn get_payload_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        self.slot_component_durations_at::<E>(slot).payload_due
    }

    /// Spec: `get_payload_attestation_due_ms`.
    pub fn get_payload_attestation_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        self.slot_component_durations_at::<E>(slot)
            .payload_attestation_due
    }

    /// Spec: `get_aggregate_attestation_due_ms`. Returns the epoch-appropriate threshold.
    pub fn get_aggregate_attestation_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        let durations = self.slot_component_durations_at::<E>(slot);
        if self.fork_name_at_slot::<E>(slot).gloas_enabled() {
            durations.aggregate_attestation_due_gloas
        } else {
            durations.aggregate_attestation_due
        }
    }

    /// Spec: `get_contribution_due_ms`. Returns the epoch-appropriate threshold.
    pub fn get_contribution_message_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        let durations = self.slot_component_durations_at::<E>(slot);
        if self.fork_name_at_slot::<E>(slot).gloas_enabled() {
            durations.contribution_and_proof_due_gloas
        } else {
            durations.contribution_and_proof_due
        }
    }

    /// Spec: `get_sync_message_due_ms`. Returns the epoch-appropriate threshold.
    pub fn get_sync_message_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        let durations = self.slot_component_durations_at::<E>(slot);
        if self.fork_name_at_slot::<E>(slot).gloas_enabled() {
            durations.sync_message_due_gloas
        } else {
            durations.sync_message_due
        }
    }

    /// Spec: `get_inclusion_list_due_ms`.
    pub fn get_inclusion_list_due<E: EthSpec>(&self, slot: Slot) -> Duration {
        self.slot_component_durations_at::<E>(slot)
            .inclusion_list_due
    }

    /// Spec: `get_proposer_reorg_cutoff_ms`.
    pub fn get_proposer_reorg_cutoff<E: EthSpec>(&self, slot: Slot) -> Duration {
        self.slot_component_durations_at::<E>(slot)
            .proposer_reorg_cutoff
    }

    fn slot_component_durations_at<E: EthSpec>(&self, slot: Slot) -> SlotComponentDurations {
        let epoch = slot.epoch(E::slots_per_epoch());
        self.slot_component_durations
            .iter()
            .take_while(|durations| epoch >= durations.epoch)
            .last()
            .copied()
            .unwrap_or_default()
    }

    /// Spec: `get_slot_component_duration_ms`.
    fn compute_slot_component_duration(
        component_basis_points: u64,
        slot_duration_ms: u64,
    ) -> Result<Duration, ArithError> {
        Ok(Duration::from_millis(
            component_basis_points
                .safe_mul(slot_duration_ms)?
                .safe_div(BASIS_POINTS)?,
        ))
    }

    fn with_slot_component_durations(mut self) -> Self {
        self.slot_component_durations =
            self.compute_slot_component_durations(self.get_slot_durations());
        self
    }

    fn compute_slot_component_durations(
        &self,
        slot_durations: impl Iterator<Item = (Epoch, u64)>,
    ) -> Vec<SlotComponentDurations> {
        slot_durations
            .map(|(epoch, slot_duration_ms)| {
                let due = |component_basis_points| {
                    Self::compute_slot_component_duration(component_basis_points, slot_duration_ms)
                        .expect("invalid chain spec: cannot compute slot component duration")
                };
                SlotComponentDurations {
                    epoch,
                    attestation_due: due(self.attestation_due_bps),
                    attestation_due_gloas: due(self.attestation_due_bps_gloas),
                    payload_due: due(self.payload_due_bps),
                    payload_attestation_due: due(self.payload_attestation_due_bps),
                    aggregate_attestation_due: due(self.aggregate_due_bps),
                    aggregate_attestation_due_gloas: due(self.aggregate_due_bps_gloas),
                    sync_message_due: due(self.sync_message_due_bps),
                    sync_message_due_gloas: due(self.sync_message_due_bps_gloas),
                    contribution_and_proof_due: due(self.contribution_due_bps),
                    contribution_and_proof_due_gloas: due(self.contribution_due_bps_gloas),
                    inclusion_list_due: due(self.inclusion_list_due_bps),
                    proposer_reorg_cutoff: due(self.proposer_reorg_cutoff_bps),
                }
            })
            .collect()
    }

    /// Returns the slot duration at genesis.
    ///
    /// Use `get_slot_duration_ms` for the slot duration at an epoch.
    pub fn genesis_slot_duration(&self) -> Duration {
        Duration::from_millis(self.slot_duration_ms)
    }

    /// Spec: `SLOT_DURATION_MS`. Rewards, penalties and churn scale relative to it.
    pub fn slot_duration_ms(&self) -> u64 {
        self.slot_duration_ms
    }

    /// Set the duration of a slot (in ms).
    pub fn set_slot_duration_ms<E: EthSpec>(mut self, slot_duration_ms: u64) -> Self {
        self.slot_duration_ms = slot_duration_ms;
        self.seconds_per_slot = slot_duration_ms.saturating_div(1000);
        self.compute_derived_values::<E>()
    }

    /// Spec: `get_slot_durations`. Returns `(epoch, slot_duration_ms)` pairs in epoch order.
    fn get_slot_durations(&self) -> impl Iterator<Item = (Epoch, u64)> {
        // EIP-8198 activates at the Heze fork.
        let eip8198 = self
            .heze_fork_epoch
            .filter(|&fork_epoch| fork_epoch != self.far_future_epoch)
            .map(|fork_epoch| (fork_epoch, self.slot_duration_ms_heze));
        std::iter::once((Epoch::new(0), self.slot_duration_ms)).chain(eip8198)
    }

    /// Spec: `compute_blob_data_retention_start_epoch`.
    pub fn compute_blob_data_retention_start_epoch<E: EthSpec>(
        &self,
        epoch: Epoch,
    ) -> Result<Epoch, ArithError> {
        let schedule = self.slot_duration_schedule();
        let current_start_ms = schedule.compute_time_at_slot_ms(
            E::slots_per_epoch(),
            0,
            epoch.start_slot(E::slots_per_epoch()),
        )?;
        let Some(window_start_ms) = current_start_ms.checked_sub(self.min_blob_data_retention_ms)
        else {
            return Ok(Epoch::new(0));
        };
        Ok(schedule
            .compute_slot_at_time_ms(E::slots_per_epoch(), 0, window_start_ms)?
            .epoch(E::slots_per_epoch()))
    }

    /// Returns the gossipsub `seen_ttl` at `epoch`: two epochs on the slot timeline, in seconds.
    pub fn gossip_seen_ttl<E: EthSpec>(&self, epoch: Epoch) -> Duration {
        let slots_per_epoch = E::slots_per_epoch();
        let schedule = self.slot_duration_schedule();
        let time_at = |epoch: Epoch| {
            schedule.compute_time_at_slot_ms(slots_per_epoch, 0, epoch.start_slot(slots_per_epoch))
        };
        let seen_ttl_ms = match (time_at(epoch), time_at(epoch.saturating_add(2u64))) {
            (Ok(start_ms), Ok(end_ms)) => end_ms.saturating_sub(start_ms),
            _ => self
                .get_slot_duration_ms(epoch)
                .saturating_mul(slots_per_epoch)
                .saturating_mul(2),
        };
        Duration::from_secs(seen_ttl_ms / 1000)
    }

    /// Spec: `get_slot_duration_ms`.
    pub fn get_slot_duration_ms(&self, epoch: Epoch) -> u64 {
        self.get_slot_durations()
            .take_while(|&(fork_epoch, _)| epoch >= fork_epoch)
            .last()
            .map_or(self.slot_duration_ms, |(_, slot_duration_ms)| {
                slot_duration_ms
            })
    }

    /// Spec: `compute_time_at_slot`. Returns the Unix time in seconds at the start of `slot`.
    pub fn compute_time_at_slot<E: EthSpec>(
        &self,
        genesis_time: u64,
        slot: Slot,
    ) -> Result<u64, ArithError> {
        self.slot_duration_schedule()
            .compute_time_at_slot_ms(E::slots_per_epoch(), genesis_time.safe_mul(1000)?, slot)?
            .safe_div(1000)
    }

    /// Spec: `compute_slot_at_time`. Returns the slot at Unix time `time` in seconds.
    pub fn compute_slot_at_time<E: EthSpec>(
        &self,
        genesis_time: u64,
        time: u64,
    ) -> Result<Slot, ArithError> {
        self.slot_duration_schedule().compute_slot_at_time_ms(
            E::slots_per_epoch(),
            genesis_time.safe_mul(1000)?,
            time.safe_mul(1000)?,
        )
    }

    pub fn slot_duration_schedule(&self) -> SlotDurationSchedule {
        Self::slot_duration_schedule_from(self.get_slot_durations())
    }

    fn slot_duration_schedule_from(
        slot_durations: impl Iterator<Item = (Epoch, u64)>,
    ) -> SlotDurationSchedule {
        let mut entries = slot_durations
            .map(|(epoch, slot_duration_ms)| SlotDurationScheduleEntry {
                epoch,
                slot_duration_ms,
            })
            .collect::<Vec<_>>();
        // Keep the last entry at each epoch, as the spec does for a fork at genesis.
        entries.reverse();
        entries.dedup_by_key(|entry| entry.epoch);
        SlotDurationSchedule::new(entries)
    }

    /// Compute values that are derived from other config values.
    ///
    /// Must be called after loading or modifying a ChainSpec's fields.
    ///
    /// Panics if any computation fails (indicates invalid config).
    pub fn compute_derived_values<E: EthSpec>(mut self) -> Self {
        assert!(
            self.attestation_due_bps <= BASIS_POINTS,
            "invalid chain spec: attestation_due_bps ({}) exceeds slot duration",
            self.attestation_due_bps
        );
        assert!(
            self.attestation_due_bps_gloas <= BASIS_POINTS,
            "invalid chain spec: attestation_due_bps_gloas ({}) exceeds slot duration",
            self.attestation_due_bps_gloas
        );
        assert!(
            self.aggregate_due_bps <= BASIS_POINTS,
            "invalid chain spec: aggregate_due_bps ({}) exceeds slot duration",
            self.aggregate_due_bps
        );
        assert!(
            self.aggregate_due_bps_gloas <= BASIS_POINTS,
            "invalid chain spec: aggregate_due_bps_gloas ({}) exceeds slot duration",
            self.aggregate_due_bps_gloas
        );
        assert!(
            self.sync_message_due_bps <= BASIS_POINTS,
            "invalid chain spec: sync_message_due_bps ({}) exceeds slot duration",
            self.sync_message_due_bps
        );
        assert!(
            self.sync_message_due_bps_gloas <= BASIS_POINTS,
            "invalid chain spec: sync_message_due_bps_gloas ({}) exceeds slot duration",
            self.sync_message_due_bps_gloas
        );
        assert!(
            self.contribution_due_bps <= BASIS_POINTS,
            "invalid chain spec: contribution_due_bps ({}) exceeds slot duration",
            self.contribution_due_bps
        );
        assert!(
            self.contribution_due_bps_gloas <= BASIS_POINTS,
            "invalid chain spec: contribution_due_bps_gloas ({}) exceeds slot duration",
            self.contribution_due_bps_gloas
        );
        assert!(
            self.payload_due_bps <= BASIS_POINTS,
            "invalid chain spec: payload_due_bps ({}) exceeds slot duration",
            self.payload_due_bps
        );
        assert!(
            self.payload_attestation_due_bps <= BASIS_POINTS,
            "invalid chain spec: payload_attestation_due_bps ({}) exceeds slot duration",
            self.payload_attestation_due_bps
        );
        assert!(
            self.inclusion_list_due_bps <= BASIS_POINTS,
            "invalid chain spec: inclusion_list_due_bps ({}) exceeds slot duration",
            self.inclusion_list_due_bps
        );
        assert!(
            self.proposer_reorg_cutoff_bps <= BASIS_POINTS,
            "invalid chain spec: proposer_reorg_cutoff_bps ({}) exceeds slot duration",
            self.proposer_reorg_cutoff_bps
        );

        self = self.with_slot_component_durations();

        self.attestation_subnet_prefix_bits = compute_attestation_subnet_prefix_bits(
            self.attestation_subnet_count,
            self.attestation_subnet_extra_bits,
        );

        self.max_blocks_by_root_request =
            max_blocks_by_root_request_common(self.max_request_blocks);
        self.max_blocks_by_root_request_deneb =
            max_blocks_by_root_request_common(self.max_request_blocks_deneb);
        self.max_blobs_by_root_request =
            max_blobs_by_root_request_common(self.max_request_blob_sidecars);
        self.max_data_columns_by_root_request =
            max_data_columns_by_root_request_common::<E>(self.max_request_blocks_deneb);
        self.max_payload_envelopes_by_root_request =
            max_blocks_by_root_request_common(self.max_request_payloads);

        self
    }

    /// Returns the slot at which the proposer shuffling was decided.
    ///
    /// The block root at this slot can be used to key the proposer shuffling for the given epoch.
    pub fn proposer_shuffling_decision_slot<E: EthSpec>(&self, epoch: Epoch) -> Slot {
        // At the Fulu fork epoch itself, the shuffling is computed "the old way" with no lookahead.
        // Therefore for `epoch == fulu_fork_epoch` we must take the `else` branch. Checking if Fulu
        // is enabled at `epoch - 1` accomplishes this neatly.
        if self
            .fork_name_at_epoch(epoch.saturating_sub(1_u64))
            .fulu_enabled()
        {
            // Post-Fulu the proposer shuffling decision slot for epoch N is the slot at the end
            // of epoch N - 2 (note: min_seed_lookahead=1 in all current configs).
            epoch
                .saturating_sub(self.min_seed_lookahead)
                .start_slot(E::slots_per_epoch())
                .saturating_sub(1_u64)
        } else {
            // Pre-Fulu the proposer shuffling decision slot for epoch N is the slot at the end of
            // epoch N - 1 (note: +1 -1 for min_seed_lookahead=1 in all current configs).
            epoch
                .saturating_add(Epoch::new(1))
                .saturating_sub(self.min_seed_lookahead)
                .start_slot(E::slots_per_epoch())
                .saturating_sub(1_u64)
        }
    }

    /// Returns a `ChainSpec` compatible with the Ethereum Foundation specification.
    pub fn mainnet() -> Self {
        Self {
            /*
             * Config name
             */
            config_name: Some("mainnet".to_string()),
            /*
             * Constants
             */
            genesis_slot: Slot::new(0),
            far_future_epoch: Epoch::new(u64::MAX),
            base_rewards_per_epoch: 4,
            deposit_contract_tree_depth: 32,

            /*
             * Misc
             */
            max_committees_per_slot: 64,
            target_committee_size: 128,
            min_per_epoch_churn_limit: 4,
            max_per_epoch_activation_churn_limit: 8,
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
            min_deposit_amount: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_effective_balance: option_wrapper(|| {
                u64::checked_pow(2, 5)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            ejection_balance: option_wrapper(|| {
                u64::checked_pow(2, 4)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            effective_balance_increment: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),

            /*
             * Initial Values
             */
            genesis_fork_version: [0; 4],
            bls_withdrawal_prefix_byte: 0x00,
            eth1_address_withdrawal_prefix_byte: 0x01,
            compounding_withdrawal_prefix_byte: 0x02,
            builder_withdrawal_prefix_byte: 0xB0,

            /*
             * Time parameters
             */
            genesis_delay: 604800, // 7 days
            seconds_per_slot: 12,
            slot_duration_ms: 12000,
            slot_duration_ms_heze: 12000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            shard_committee_period: 256,
            proposer_reorg_cutoff_bps: 1667,
            attestation_due_bps: 3333,
            attestation_due_bps_gloas: 2500,
            payload_due_bps: 5000,
            payload_attestation_due_bps: 7500,
            aggregate_due_bps: 6667,
            aggregate_due_bps_gloas: 5000,
            sync_message_due_bps: 3333,
            sync_message_due_bps_gloas: 2500,
            contribution_due_bps: 6667,
            contribution_due_bps_gloas: 5000,
            inclusion_list_due_bps: 7500,
            slot_component_durations: vec![],

            /*
             * Reward and penalty quotients
             */
            base_reward_factor: 64,
            whistleblower_reward_quotient: 512,
            proposer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::checked_pow(2, 26).expect("pow does not overflow"),
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
            domain_beacon_builder: 0x0B,
            domain_ptc_attester: 0x0C,
            domain_proposer_preferences: 0x0D,
            domain_builder_deposit: 0x0E,
            domain_inclusion_list_committee: 0x10,
            domain_execution_proof: 0x0F,

            /*
             * Fork choice
             */
            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            /*
             * Fast confirmation rule
             */
            confirmation_byzantine_threshold: 25,

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
             * Execution Specs
             */
            gas_limit_adjustment_factor: 1024,

            /*
             * Altair hard fork params
             */
            inactivity_penalty_quotient_altair: option_wrapper(|| {
                u64::checked_pow(2, 24)?.checked_mul(3)
            })
            .expect("calculation does not overflow"),
            min_slashing_penalty_quotient_altair: u64::checked_pow(2, 6)
                .expect("pow does not overflow"),
            proportional_slashing_multiplier_altair: 2,
            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            min_sync_committee_participants: 1,
            update_timeout: 8192,
            epochs_per_sync_committee_period: Epoch::new(256),
            domain_sync_committee: 7,
            domain_sync_committee_selection_proof: 8,
            domain_contribution_and_proof: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            altair_fork_epoch: Some(Epoch::new(74240)),

            /*
             * Bellatrix hard fork params
             */
            inactivity_penalty_quotient_bellatrix: u64::checked_pow(2, 24)
                .expect("pow does not overflow"),
            min_slashing_penalty_quotient_bellatrix: u64::checked_pow(2, 5)
                .expect("pow does not overflow"),
            proportional_slashing_multiplier_bellatrix: 3,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: Some(Epoch::new(144896)),
            terminal_total_difficulty: "58750000000000000000000"
                .parse()
                .expect("terminal_total_difficulty is a valid integer"),
            terminal_block_hash: ExecutionBlockHash::zero(),
            terminal_block_hash_activation_epoch: Epoch::new(u64::MAX),

            /*
             * Capella hard fork params
             */
            capella_fork_version: [0x03, 00, 00, 00],
            capella_fork_epoch: Some(Epoch::new(194048)),
            max_validators_per_withdrawals_sweep: 16384,

            /*
             * Deneb hard fork params
             */
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            deneb_fork_epoch: Some(Epoch::new(269568)),

            /*
             * Electra hard fork params
             */
            electra_fork_version: [0x05, 00, 00, 00],
            electra_fork_epoch: Some(Epoch::new(364032)),
            unset_deposit_requests_start_index: u64::MAX,
            full_exit_request_amount: 0,
            min_activation_balance: option_wrapper(|| {
                u64::checked_pow(2, 5)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_effective_balance_electra: option_wrapper(|| {
                u64::checked_pow(2, 11)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            min_slashing_penalty_quotient_electra: u64::checked_pow(2, 12)
                .expect("pow does not overflow"),
            whistleblower_reward_quotient_electra: u64::checked_pow(2, 12)
                .expect("pow does not overflow"),
            max_pending_partials_per_withdrawals_sweep: u64::checked_pow(2, 3)
                .expect("pow does not overflow"),
            min_per_epoch_churn_limit_electra: option_wrapper(|| {
                u64::checked_pow(2, 7)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_per_epoch_activation_exit_churn_limit: option_wrapper(|| {
                u64::checked_pow(2, 8)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),

            /*
             * Fulu hard fork params
             */
            fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
            fulu_fork_epoch: Some(Epoch::new(411392)),
            custody_requirement: 4,
            number_of_custody_groups: 128,
            data_column_sidecar_subnet_count: 128,
            samples_per_slot: 8,
            validator_custody_requirement: 8,
            balance_per_additional_custody_group: 32000000000,

            /*
             * Gloas hard fork params
             */
            gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
            gloas_fork_epoch: None,
            builder_payment_threshold_numerator: 6,
            builder_payment_threshold_denominator: 10,
            min_builder_withdrawability_delay: Epoch::new(64),
            churn_limit_quotient_gloas: option_wrapper(|| u64::checked_pow(2, 15))
                .expect("calculation does not overflow"),
            consolidation_churn_limit_quotient: option_wrapper(|| u64::checked_pow(2, 16))
                .expect("calculation does not overflow"),
            max_per_epoch_activation_churn_limit_gloas: option_wrapper(|| {
                u64::checked_pow(2, 8)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            gas_limit_schedule: GasLimitSchedule::default(),
            max_request_payloads: 128,

            /*
             * Heze hard fork params
             */
            heze_fork_version: [0x08, 0x00, 0x00, 0x00],
            heze_fork_epoch: None,
            max_transactions_bytes_per_inclusion_list: 8192,
            max_request_inclusion_list: 16,
            min_slots_for_inclusion_lists_requests: 1,

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 1, // mainnet network id
            attestation_propagation_slot_range: default_attestation_propagation_slot_range(),
            epochs_per_subnet_subscription: 256,
            attestation_subnet_count: 64,
            attestation_subnet_extra_bits: 0,
            subnets_per_node: 2,
            maximum_gossip_clock_disparity: default_maximum_gossip_clock_disparity(),
            target_aggregators_per_committee: 16,
            max_payload_size: default_max_payload_size(),
            min_epochs_for_block_requests: default_min_epochs_for_block_requests(),
            ttfb_timeout: default_ttfb_timeout(),
            resp_timeout: default_resp_timeout(),
            message_domain_invalid_snappy: default_message_domain_invalid_snappy(),
            message_domain_valid_snappy: default_message_domain_valid_snappy(),
            attestation_subnet_prefix_bits: compute_attestation_subnet_prefix_bits(
                default_attestation_subnet_count(),
                default_attestation_subnet_extra_bits(),
            ),
            max_request_blocks: default_max_request_blocks(),

            /*
             * Networking Deneb Specific
             */
            max_request_blocks_deneb: default_max_request_blocks_deneb(),
            max_request_blob_sidecars: default_max_request_blob_sidecars(),
            max_request_data_column_sidecars: default_max_request_data_column_sidecars(),
            min_epochs_for_blob_sidecars_requests: default_min_epochs_for_blob_sidecars_requests(),
            blob_sidecar_subnet_count: default_blob_sidecar_subnet_count(),
            max_blobs_per_block: default_max_blobs_per_block(),

            /*
             * Derived Deneb Specific
             */
            max_blocks_by_root_request: default_max_blocks_by_root_request(),
            max_blocks_by_root_request_deneb: default_max_blocks_by_root_request_deneb(),
            max_blobs_by_root_request: default_max_blobs_by_root_request(),

            /*
             * Networking Electra specific
             */
            max_blobs_per_block_electra: default_max_blobs_per_block_electra(),
            blob_sidecar_subnet_count_electra: default_blob_sidecar_subnet_count_electra(),
            max_request_blob_sidecars_electra: default_max_request_blob_sidecars_electra(),

            /*
             * Networking Fulu specific
             */
            blob_schedule: BlobSchedule::new(vec![
                BlobParameters {
                    epoch: Epoch::new(412672),
                    max_blobs_per_block: 15,
                },
                BlobParameters {
                    epoch: Epoch::new(419072),
                    max_blobs_per_block: 21,
                },
            ]),
            min_epochs_for_data_column_sidecars_requests:
                default_min_epochs_for_data_column_sidecars_requests(),
            min_blob_data_retention_ms: default_min_blob_data_retention_ms(),
            max_data_columns_by_root_request: default_data_columns_by_root_request(),
            max_payload_envelopes_by_root_request: default_max_payload_envelopes_by_root_request(),

            /*
             * Application specific
             */
            domain_application_mask: APPLICATION_DOMAIN_BUILDER,

            /*
             * Capella params
             */
            domain_bls_to_execution_change: 10,
        }
        .with_slot_component_durations()
    }

    /// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
    pub fn minimal() -> Self {
        // Note: bootnodes to be updated when static nodes exist.
        let boot_nodes = vec![];

        Self {
            config_name: None,
            max_committees_per_slot: 4,
            target_committee_size: 4,
            min_per_epoch_churn_limit: 2,
            max_per_epoch_activation_churn_limit: 4,
            churn_limit_quotient: 32,
            shuffle_round_count: 10,
            min_genesis_active_validator_count: 64,
            min_genesis_time: 1578009600,
            eth1_follow_distance: 16,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
            shard_committee_period: 64,
            genesis_delay: 300,
            seconds_per_slot: 6,
            slot_duration_ms: 6000,
            slot_duration_ms_heze: 5000,
            inactivity_penalty_quotient: u64::checked_pow(2, 25).expect("pow does not overflow"),
            min_slashing_penalty_quotient: 64,
            proportional_slashing_multiplier: 2,
            // Altair
            epochs_per_sync_committee_period: Epoch::new(8),
            update_timeout: 64,
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            altair_fork_epoch: None,
            // Bellatrix
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            bellatrix_fork_epoch: None,
            terminal_total_difficulty: Uint256::MAX
                .checked_sub(Uint256::from(2u64.pow(10)))
                .expect("subtraction does not overflow")
                // Add 1 since the spec declares `2**256 - 2**10` and we use
                // `Uint256::MAX` which is `2*256- 1`.
                .checked_add(Uint256::from(2u64.pow(0)))
                .expect("addition does not overflow"),
            // Capella
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            capella_fork_epoch: None,
            max_validators_per_withdrawals_sweep: 16,
            // Deneb
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            deneb_fork_epoch: None,
            // Electra
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            electra_fork_epoch: None,
            max_pending_partials_per_withdrawals_sweep: u64::checked_pow(2, 1)
                .expect("pow does not overflow"),
            min_per_epoch_churn_limit_electra: option_wrapper(|| {
                u64::checked_pow(2, 6)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_per_epoch_activation_exit_churn_limit: option_wrapper(|| {
                u64::checked_pow(2, 7)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            // Fulu
            fulu_fork_version: [0x06, 0x00, 0x00, 0x01],
            fulu_fork_epoch: None,
            // Gloas
            gloas_fork_version: [0x07, 0x00, 0x00, 0x01],
            gloas_fork_epoch: None,
            min_builder_withdrawability_delay: Epoch::new(2),
            churn_limit_quotient_gloas: option_wrapper(|| u64::checked_pow(2, 4))
                .expect("calculation does not overflow"),
            consolidation_churn_limit_quotient: option_wrapper(|| u64::checked_pow(2, 5))
                .expect("calculation does not overflow"),
            max_per_epoch_activation_churn_limit_gloas: option_wrapper(|| {
                u64::checked_pow(2, 7)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            gas_limit_schedule: GasLimitSchedule::default(),
            // Heze
            heze_fork_version: [0x08, 0x00, 0x00, 0x01],
            heze_fork_epoch: None,

            // Networking Fulu
            blob_schedule: BlobSchedule::default(),
            min_blob_data_retention_ms: 196608000,

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
        .with_slot_component_durations()
    }

    /// Returns a `ChainSpec` compatible with the Gnosis Beacon Chain specification.
    pub fn gnosis() -> Self {
        Self {
            config_name: Some("gnosis".to_string()),
            /*
             * Constants
             */
            genesis_slot: Slot::new(0),
            far_future_epoch: Epoch::new(u64::MAX),
            base_rewards_per_epoch: 4,
            deposit_contract_tree_depth: 32,

            /*
             * Misc
             */
            max_committees_per_slot: 64,
            target_committee_size: 128,
            min_per_epoch_churn_limit: 4,
            max_per_epoch_activation_churn_limit: 2,
            churn_limit_quotient: 4_096,
            shuffle_round_count: 90,
            min_genesis_active_validator_count: 4_096,
            min_genesis_time: 1638968400, // Dec 8, 2020
            hysteresis_quotient: 4,
            hysteresis_downward_multiplier: 1,
            hysteresis_upward_multiplier: 5,

            /*
             *  Gwei values
             */
            min_deposit_amount: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_effective_balance: option_wrapper(|| {
                u64::checked_pow(2, 5)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            ejection_balance: option_wrapper(|| {
                u64::checked_pow(2, 4)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            effective_balance_increment: option_wrapper(|| {
                u64::checked_pow(2, 0)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),

            /*
             * Initial Values
             */
            genesis_fork_version: [0x00, 0x00, 0x00, 0x64],
            bls_withdrawal_prefix_byte: 0x00,
            eth1_address_withdrawal_prefix_byte: 0x01,
            compounding_withdrawal_prefix_byte: 0x02,
            builder_withdrawal_prefix_byte: 0xB0,

            /*
             * Time parameters
             */
            genesis_delay: 6000, // 100 minutes
            seconds_per_slot: 5,
            slot_duration_ms: 5000,
            slot_duration_ms_heze: 5000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            shard_committee_period: 256,
            proposer_reorg_cutoff_bps: 1667,
            attestation_due_bps: 3333,
            attestation_due_bps_gloas: 2500,
            payload_due_bps: 5000,
            payload_attestation_due_bps: 7500,
            aggregate_due_bps: 6667,
            aggregate_due_bps_gloas: 5000,

            /*
             * Reward and penalty quotients
             */
            base_reward_factor: 25,
            whistleblower_reward_quotient: 512,
            proposer_reward_quotient: 8,
            inactivity_penalty_quotient: u64::checked_pow(2, 26).expect("pow does not overflow"),
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
            domain_beacon_builder: 0x0B,
            domain_ptc_attester: 0x0C,
            domain_proposer_preferences: 0x0D,
            domain_builder_deposit: 0x0E,
            domain_inclusion_list_committee: 0x10,
            domain_execution_proof: 0x0F,

            /*
             * Fork choice
             */
            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            /*
             * Fast confirmation rule
             */
            confirmation_byzantine_threshold: 25,

            /*
             * Eth1
             */
            eth1_follow_distance: 1024,
            seconds_per_eth1_block: 6,
            deposit_chain_id: 100,
            deposit_network_id: 100,
            deposit_contract_address: "0B98057eA310F4d31F2a452B414647007d1645d9"
                .parse()
                .expect("chain spec deposit contract address"),

            /*
             * Execution Specs
             */
            gas_limit_adjustment_factor: 1024,

            /*
             * Altair hard fork params
             */
            inactivity_penalty_quotient_altair: option_wrapper(|| {
                u64::checked_pow(2, 24)?.checked_mul(3)
            })
            .expect("calculation does not overflow"),
            min_slashing_penalty_quotient_altair: u64::checked_pow(2, 6)
                .expect("pow does not overflow"),
            proportional_slashing_multiplier_altair: 2,
            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            min_sync_committee_participants: 1,
            update_timeout: 8192,
            epochs_per_sync_committee_period: Epoch::new(512),
            domain_sync_committee: 7,
            domain_sync_committee_selection_proof: 8,
            domain_contribution_and_proof: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x64],
            altair_fork_epoch: Some(Epoch::new(512)),
            sync_message_due_bps: 3333,
            sync_message_due_bps_gloas: 2500,
            contribution_due_bps: 6667,
            contribution_due_bps_gloas: 5000,
            inclusion_list_due_bps: 7500,
            slot_component_durations: vec![],

            /*
             * Bellatrix hard fork params
             */
            inactivity_penalty_quotient_bellatrix: u64::checked_pow(2, 24)
                .expect("pow does not overflow"),
            min_slashing_penalty_quotient_bellatrix: u64::checked_pow(2, 5)
                .expect("pow does not overflow"),
            proportional_slashing_multiplier_bellatrix: 3,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x64],
            bellatrix_fork_epoch: Some(Epoch::new(385536)),
            terminal_total_difficulty: "8626000000000000000000058750000000000000000000"
                .parse()
                .expect("terminal_total_difficulty is a valid integer"),
            terminal_block_hash: ExecutionBlockHash::zero(),
            terminal_block_hash_activation_epoch: Epoch::new(u64::MAX),

            /*
             * Capella hard fork params
             */
            capella_fork_version: [0x03, 0x00, 0x00, 0x64],
            capella_fork_epoch: Some(Epoch::new(648704)),
            max_validators_per_withdrawals_sweep: 8192,

            /*
             * Deneb hard fork params
             */
            deneb_fork_version: [0x04, 0x00, 0x00, 0x64],
            deneb_fork_epoch: Some(Epoch::new(889856)),

            /*
             * Electra hard fork params
             */
            electra_fork_version: [0x05, 0x00, 0x00, 0x64],
            electra_fork_epoch: Some(Epoch::new(1337856)),
            unset_deposit_requests_start_index: u64::MAX,
            full_exit_request_amount: 0,
            min_activation_balance: option_wrapper(|| {
                u64::checked_pow(2, 5)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_effective_balance_electra: option_wrapper(|| {
                u64::checked_pow(2, 11)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            min_slashing_penalty_quotient_electra: u64::checked_pow(2, 12)
                .expect("pow does not overflow"),
            whistleblower_reward_quotient_electra: u64::checked_pow(2, 12)
                .expect("pow does not overflow"),
            max_pending_partials_per_withdrawals_sweep: 6,
            min_per_epoch_churn_limit_electra: option_wrapper(|| {
                u64::checked_pow(2, 7)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            max_per_epoch_activation_exit_churn_limit: option_wrapper(|| {
                u64::checked_pow(2, 6)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),

            /*
             * Fulu hard fork params
             */
            fulu_fork_version: [0x06, 0x00, 0x00, 0x64],
            fulu_fork_epoch: Some(Epoch::new(1714688)),
            custody_requirement: 4,
            number_of_custody_groups: 128,
            data_column_sidecar_subnet_count: 128,
            samples_per_slot: 8,
            validator_custody_requirement: 8,
            balance_per_additional_custody_group: 32000000000,

            /*
             * Gloas hard fork params
             */
            gloas_fork_version: [0x07, 0x00, 0x00, 0x64],
            gloas_fork_epoch: None,
            builder_payment_threshold_numerator: 6,
            builder_payment_threshold_denominator: 10,
            min_builder_withdrawability_delay: Epoch::new(64),
            churn_limit_quotient_gloas: option_wrapper(|| u64::checked_pow(2, 15))
                .expect("calculation does not overflow"),
            consolidation_churn_limit_quotient: option_wrapper(|| u64::checked_pow(2, 16))
                .expect("calculation does not overflow"),
            max_per_epoch_activation_churn_limit_gloas: option_wrapper(|| {
                u64::checked_pow(2, 8)?.checked_mul(u64::checked_pow(10, 9)?)
            })
            .expect("calculation does not overflow"),
            gas_limit_schedule: GasLimitSchedule::default(),
            max_request_payloads: 128,

            /*
             * Heze hard fork params
             */
            heze_fork_version: [0x08, 0x00, 0x00, 0x64],
            heze_fork_epoch: None,
            max_transactions_bytes_per_inclusion_list: 8192,
            max_request_inclusion_list: 16,
            min_slots_for_inclusion_lists_requests: 1,

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 100, // Gnosis Chain network id
            attestation_propagation_slot_range: default_attestation_propagation_slot_range(),
            epochs_per_subnet_subscription: 256,
            attestation_subnet_count: 64,
            attestation_subnet_extra_bits: 0,
            subnets_per_node: 4, // Make this larger than usual to avoid network damage
            maximum_gossip_clock_disparity: default_maximum_gossip_clock_disparity(),
            target_aggregators_per_committee: 16,
            max_payload_size: default_max_payload_size(),
            min_epochs_for_block_requests: 33024,
            ttfb_timeout: default_ttfb_timeout(),
            resp_timeout: default_resp_timeout(),
            message_domain_invalid_snappy: default_message_domain_invalid_snappy(),
            message_domain_valid_snappy: default_message_domain_valid_snappy(),
            max_request_blocks: default_max_request_blocks(),
            attestation_subnet_prefix_bits: compute_attestation_subnet_prefix_bits(
                default_attestation_subnet_count(),
                default_attestation_subnet_extra_bits(),
            ),

            /*
             * Networking Deneb Specific
             */
            max_request_blocks_deneb: default_max_request_blocks_deneb(),
            max_request_blob_sidecars: default_max_request_blob_sidecars(),
            max_request_data_column_sidecars: default_max_request_data_column_sidecars(),
            min_epochs_for_blob_sidecars_requests: 16384,
            blob_sidecar_subnet_count: default_blob_sidecar_subnet_count(),
            max_blobs_per_block: 2,

            /*
             * Derived Deneb Specific
             */
            max_blocks_by_root_request: default_max_blocks_by_root_request(),
            max_blocks_by_root_request_deneb: default_max_blocks_by_root_request_deneb(),
            max_blobs_by_root_request: default_max_blobs_by_root_request(),

            /*
             * Networking Electra specific
             */
            max_blobs_per_block_electra: 2,
            blob_sidecar_subnet_count_electra: 2,
            max_request_blob_sidecars_electra: 256,

            /*
             * Networking Fulu specific
             */
            blob_schedule: BlobSchedule::default(),
            min_epochs_for_data_column_sidecars_requests: 16384,
            min_blob_data_retention_ms: 1310720000,
            max_data_columns_by_root_request: default_data_columns_by_root_request(),
            max_payload_envelopes_by_root_request: default_max_payload_envelopes_by_root_request(),

            /*
             * Application specific
             */
            domain_application_mask: APPLICATION_DOMAIN_BUILDER,

            /*
             * Capella params
             */
            domain_bls_to_execution_change: 10,
        }
        .with_slot_component_durations()
    }
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self::mainnet()
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct BlobParameters {
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub max_blobs_per_block: u64,
}

/// The gas limit execution clients use by default. The last resort when neither the operator nor
/// the gas limit schedule gives a value.
///
/// https://ethpandaops.io/posts/gaslimit-scaling/.
pub const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

pub trait ScheduleEntry {
    fn epoch(&self) -> Epoch;
}

impl ScheduleEntry for BlobParameters {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct GasLimitScheduleEntry {
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
}

impl ScheduleEntry for GasLimitScheduleEntry {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Debug, Clone, Copy, Default)]
struct SlotComponentDurations {
    epoch: Epoch,
    attestation_due: Duration,
    attestation_due_gloas: Duration,
    payload_due: Duration,
    payload_attestation_due: Duration,
    aggregate_attestation_due: Duration,
    aggregate_attestation_due_gloas: Duration,
    sync_message_due: Duration,
    sync_message_due_gloas: Duration,
    contribution_and_proof_due: Duration,
    contribution_and_proof_due_gloas: Duration,
    inclusion_list_due: Duration,
    proposer_reorg_cutoff: Duration,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SlotDurationScheduleEntry {
    pub epoch: Epoch,
    pub slot_duration_ms: u64,
}

impl ScheduleEntry for SlotDurationScheduleEntry {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

pub type BlobSchedule = EpochSchedule<BlobParameters>;
pub type GasLimitSchedule = EpochSchedule<GasLimitScheduleEntry>;
pub type SlotDurationSchedule = EpochSchedule<SlotDurationScheduleEntry>;

// A wrapper around a vector of schedule entries to ensure that the vector is reverse sorted by
// epoch.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq)]
pub struct EpochSchedule<T> {
    schedule: Vec<T>,
    // This is a hack to prevent the schedule being serialized on the /eth/v1/config/spec
    // endpoint prior to its fork being scheduled.
    #[educe(PartialEq(ignore))]
    skip_serializing: bool,
}

impl<'de, T: ScheduleEntry + Deserialize<'de>> Deserialize<'de> for EpochSchedule<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<T>::deserialize(deserializer)?;
        Ok(EpochSchedule::new(vec))
    }
}

impl<T: ScheduleEntry> EpochSchedule<T> {
    pub fn new(mut vec: Vec<T>) -> Self {
        // reverse sort by epoch
        vec.sort_by_key(|entry| std::cmp::Reverse(entry.epoch()));
        Self {
            schedule: vec,
            skip_serializing: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.schedule.is_empty()
    }

    pub fn skip_serializing(&self) -> bool {
        self.skip_serializing
    }

    pub fn set_skip_serializing(&mut self) {
        self.skip_serializing = true;
    }

    pub fn entry_for_epoch(&self, epoch: Epoch) -> Option<&T> {
        self.schedule.iter().find(|entry| epoch >= entry.epoch())
    }

    pub const fn default() -> Self {
        Self {
            schedule: vec![],
            skip_serializing: false,
        }
    }

    pub fn as_vec(&self) -> &Vec<T> {
        &self.schedule
    }
}

impl BlobSchedule {
    pub fn max_blobs_for_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.entry_for_epoch(epoch)
            .map(|entry| entry.max_blobs_per_block)
    }

    pub fn blob_parameters_for_epoch(&self, epoch: Epoch) -> Option<BlobParameters> {
        self.entry_for_epoch(epoch).cloned()
    }
}

impl GasLimitSchedule {
    pub fn gas_limit_for_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.entry_for_epoch(epoch).map(|entry| entry.gas_limit)
    }
}

impl SlotDurationSchedule {
    pub fn slot_duration_ms_for_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.entry_for_epoch(epoch)
            .map(|entry| entry.slot_duration_ms)
    }

    /// Spec: `compute_time_at_slot_ms`. Returns `ArithError::Overflow` for an empty schedule.
    pub fn compute_time_at_slot_ms(
        &self,
        slots_per_epoch: u64,
        genesis_time_ms: u64,
        slot: Slot,
    ) -> Result<u64, ArithError> {
        let mut entries = self.as_vec().iter().rev();
        let genesis = entries.next().ok_or(ArithError::Overflow)?;
        let mut start_slot = genesis.epoch.start_slot(slots_per_epoch);
        let mut start_time_ms = genesis_time_ms;
        let mut slot_duration_ms = genesis.slot_duration_ms;
        for entry in entries {
            let entry_slot = entry.epoch.start_slot(slots_per_epoch);
            if slot <= entry_slot {
                break;
            }
            start_time_ms.safe_add_assign(
                entry_slot
                    .safe_sub(start_slot)?
                    .as_u64()
                    .safe_mul(slot_duration_ms)?,
            )?;
            start_slot = entry_slot;
            slot_duration_ms = entry.slot_duration_ms;
        }
        start_time_ms.safe_add(
            slot.safe_sub(start_slot)?
                .as_u64()
                .safe_mul(slot_duration_ms)?,
        )
    }

    /// Spec: `compute_slot_at_time_ms`. Returns `ArithError::Overflow` for an empty schedule.
    pub fn compute_slot_at_time_ms(
        &self,
        slots_per_epoch: u64,
        genesis_time_ms: u64,
        time_ms: u64,
    ) -> Result<Slot, ArithError> {
        let mut entries = self.as_vec().iter().rev();
        let genesis = entries.next().ok_or(ArithError::Overflow)?;
        let mut start_slot = genesis.epoch.start_slot(slots_per_epoch);
        let mut start_time_ms = genesis_time_ms;
        let mut slot_duration_ms = genesis.slot_duration_ms;
        for entry in entries {
            let entry_slot = entry.epoch.start_slot(slots_per_epoch);
            let Some(entry_time_ms) = entry_slot
                .as_u64()
                .checked_sub(start_slot.as_u64())
                .and_then(|slots| slots.checked_mul(slot_duration_ms))
                .and_then(|duration_ms| start_time_ms.checked_add(duration_ms))
            else {
                break;
            };
            if time_ms < entry_time_ms {
                break;
            }
            start_slot = entry_slot;
            start_time_ms = entry_time_ms;
            slot_duration_ms = entry.slot_duration_ms;
        }
        let slots = time_ms
            .safe_sub(start_time_ms)?
            .safe_div(slot_duration_ms)?;
        start_slot.safe_add(slots)
    }
}

impl<T: Serialize + Clone> Serialize for EpochSchedule<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut schedule = self.schedule.clone();
        // reversing the list to get an ascending order
        schedule.reverse();
        schedule.serialize(serializer)
    }
}

impl<'a, T> IntoIterator for &'a EpochSchedule<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.schedule.iter()
    }
}

impl<T> IntoIterator for EpochSchedule<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.schedule.into_iter()
    }
}

/// Exact implementation of the *config* object from the Ethereum spec (YAML/JSON).
///
/// Fields relevant to hard forks after Altair should be optional so that we can continue
/// to parse Altair configs. This default approach turns out to be much simpler than trying to
/// make `Config` a superstruct because of the hassle of deserializing an untagged enum.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Config {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_name: Option<String>,

    #[serde(default)]
    pub preset_base: String,

    #[serde(default = "default_terminal_total_difficulty")]
    #[serde(with = "serde_utils::quoted_u256")]
    pub terminal_total_difficulty: Uint256,
    #[serde(default = "default_terminal_block_hash")]
    pub terminal_block_hash: ExecutionBlockHash,
    #[serde(default = "default_terminal_block_hash_activation_epoch")]
    pub terminal_block_hash_activation_epoch: Epoch,

    #[serde(with = "serde_utils::quoted_u64")]
    min_genesis_active_validator_count: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_genesis_time: u64,
    #[serde(with = "serde_utils::bytes_4_hex")]
    genesis_fork_version: [u8; 4],
    #[serde(with = "serde_utils::quoted_u64")]
    genesis_delay: u64,

    #[serde(with = "serde_utils::bytes_4_hex")]
    altair_fork_version: [u8; 4],
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub altair_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_bellatrix_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    bellatrix_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub bellatrix_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_capella_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    capella_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub capella_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_deneb_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    deneb_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub deneb_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_electra_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    electra_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub electra_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_fulu_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    fulu_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub fulu_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_gloas_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    gloas_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub gloas_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default = "default_heze_fork_version")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    heze_fork_version: [u8; 4],
    #[serde(default)]
    #[serde(serialize_with = "serialize_fork_epoch")]
    #[serde(deserialize_with = "deserialize_fork_epoch")]
    pub heze_fork_epoch: Option<MaybeQuoted<Epoch>>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_per_slot: Option<MaybeQuoted<u64>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_duration_ms: Option<MaybeQuoted<u64>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_duration_ms_heze: Option<MaybeQuoted<u64>>,
    #[serde(with = "serde_utils::quoted_u64")]
    seconds_per_eth1_block: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_validator_withdrawability_delay: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    shard_committee_period: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    eth1_follow_distance: u64,
    #[serde(default = "default_subnets_per_node")]
    #[serde(with = "serde_utils::quoted_u8")]
    subnets_per_node: u8,

    #[serde(with = "serde_utils::quoted_u64")]
    inactivity_score_bias: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    inactivity_score_recovery_rate: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    ejection_balance: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    min_per_epoch_churn_limit: u64,
    #[serde(default = "default_max_per_epoch_activation_churn_limit")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_per_epoch_activation_churn_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    churn_limit_quotient: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    proposer_score_boost: Option<MaybeQuoted<u64>>,

    #[serde(default = "default_confirmation_byzantine_threshold")]
    #[serde(with = "serde_utils::quoted_u64")]
    confirmation_byzantine_threshold: u64,
    #[serde(default = "default_reorg_head_weight_threshold")]
    #[serde(with = "serde_utils::quoted_u64")]
    reorg_head_weight_threshold: u64,
    #[serde(default = "default_reorg_parent_weight_threshold")]
    #[serde(with = "serde_utils::quoted_u64")]
    reorg_parent_weight_threshold: u64,
    #[serde(default = "default_reorg_max_epochs_since_finalization")]
    #[serde(with = "serde_utils::quoted_u64")]
    reorg_max_epochs_since_finalization: u64,

    #[serde(with = "serde_utils::quoted_u64")]
    deposit_chain_id: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    deposit_network_id: u64,
    #[serde(with = "serde_utils::address_hex")]
    deposit_contract_address: Address,

    #[serde(default = "default_gas_limit_adjustment_factor")]
    #[serde(with = "serde_utils::quoted_u64")]
    gas_limit_adjustment_factor: u64,

    #[serde(default = "default_max_payload_size")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_payload_size: u64,
    #[serde(default = "default_max_request_blocks")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_blocks: u64,
    #[serde(default = "default_min_epochs_for_block_requests")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_epochs_for_block_requests: u64,
    #[serde(default = "default_ttfb_timeout")]
    #[serde(with = "serde_utils::quoted_u64")]
    ttfb_timeout: u64,
    #[serde(default = "default_resp_timeout")]
    #[serde(with = "serde_utils::quoted_u64")]
    resp_timeout: u64,
    #[serde(default = "default_attestation_propagation_slot_range")]
    #[serde(with = "serde_utils::quoted_u64")]
    attestation_propagation_slot_range: u64,
    #[serde(default = "default_maximum_gossip_clock_disparity")]
    #[serde(with = "serde_utils::quoted_u64")]
    maximum_gossip_clock_disparity: u64,
    #[serde(default = "default_message_domain_invalid_snappy")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    message_domain_invalid_snappy: [u8; 4],
    #[serde(default = "default_message_domain_valid_snappy")]
    #[serde(with = "serde_utils::bytes_4_hex")]
    message_domain_valid_snappy: [u8; 4],
    #[serde(default = "default_epochs_per_subnet_subscription")]
    #[serde(with = "serde_utils::quoted_u64")]
    epochs_per_subnet_subscription: u64,
    #[serde(default = "default_attestation_subnet_count")]
    #[serde(with = "serde_utils::quoted_u64")]
    attestation_subnet_count: u64,
    #[serde(default = "default_attestation_subnet_extra_bits")]
    #[serde(with = "serde_utils::quoted_u8")]
    attestation_subnet_extra_bits: u8,
    #[serde(default = "default_max_request_blocks_deneb")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_blocks_deneb: u64,
    #[serde(default = "default_max_request_blob_sidecars")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_blob_sidecars: u64,
    #[serde(default = "default_max_request_data_column_sidecars")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_data_column_sidecars: u64,
    #[serde(default = "default_min_epochs_for_blob_sidecars_requests")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_epochs_for_blob_sidecars_requests: u64,
    #[serde(default = "default_blob_sidecar_subnet_count")]
    #[serde(with = "serde_utils::quoted_u64")]
    blob_sidecar_subnet_count: u64,
    #[serde(default = "default_max_blobs_per_block")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_blobs_per_block: u64,

    #[serde(default = "default_min_per_epoch_churn_limit_electra")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_per_epoch_churn_limit_electra: u64,
    #[serde(default = "default_max_per_epoch_activation_exit_churn_limit")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_per_epoch_activation_exit_churn_limit: u64,
    #[serde(default = "default_max_blobs_per_block_electra")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_blobs_per_block_electra: u64,
    #[serde(default = "default_blob_sidecar_subnet_count_electra")]
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_sidecar_subnet_count_electra: u64,
    #[serde(default = "default_max_request_blob_sidecars_electra")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_blob_sidecars_electra: u64,

    #[serde(default = "default_number_of_custody_groups")]
    #[serde(with = "serde_utils::quoted_u64")]
    number_of_custody_groups: u64,
    #[serde(default = "default_data_column_sidecar_subnet_count")]
    #[serde(with = "serde_utils::quoted_u64")]
    data_column_sidecar_subnet_count: u64,
    #[serde(default = "default_samples_per_slot")]
    #[serde(with = "serde_utils::quoted_u64")]
    samples_per_slot: u64,
    #[serde(default = "default_custody_requirement")]
    #[serde(with = "serde_utils::quoted_u64")]
    custody_requirement: u64,
    #[serde(default = "BlobSchedule::default")]
    #[serde(skip_serializing_if = "BlobSchedule::skip_serializing")]
    pub blob_schedule: BlobSchedule,
    #[serde(default = "default_validator_custody_requirement")]
    #[serde(with = "serde_utils::quoted_u64")]
    validator_custody_requirement: u64,
    #[serde(default = "default_balance_per_additional_custody_group")]
    #[serde(with = "serde_utils::quoted_u64")]
    balance_per_additional_custody_group: u64,
    #[serde(default = "default_min_epochs_for_data_column_sidecars_requests")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_epochs_for_data_column_sidecars_requests: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    min_blob_data_retention_ms: Option<MaybeQuoted<u64>>,

    #[serde(default = "default_proposer_reorg_cutoff_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    proposer_reorg_cutoff_bps: u64,
    #[serde(default = "default_attestation_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    attestation_due_bps: u64,
    #[serde(default = "default_attestation_due_bps_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    attestation_due_bps_gloas: u64,
    #[serde(default = "default_payload_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    payload_due_bps: u64,
    #[serde(default = "default_payload_attestation_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    payload_attestation_due_bps: u64,
    #[serde(default = "default_aggregate_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    aggregate_due_bps: u64,
    #[serde(default = "default_aggregate_due_bps_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    aggregate_due_bps_gloas: u64,
    #[serde(default = "default_sync_message_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    sync_message_due_bps: u64,
    #[serde(default = "default_sync_message_due_bps_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    sync_message_due_bps_gloas: u64,
    #[serde(default = "default_contribution_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    contribution_due_bps: u64,
    #[serde(default = "default_contribution_due_bps_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    contribution_due_bps_gloas: u64,
    #[serde(default = "default_inclusion_list_due_bps")]
    #[serde(with = "serde_utils::quoted_u64")]
    inclusion_list_due_bps: u64,

    #[serde(default = "default_min_builder_withdrawability_delay")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_builder_withdrawability_delay: u64,

    #[serde(default = "default_churn_limit_quotient_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    churn_limit_quotient_gloas: u64,
    #[serde(default = "default_consolidation_churn_limit_quotient")]
    #[serde(with = "serde_utils::quoted_u64")]
    consolidation_churn_limit_quotient: u64,
    #[serde(default = "default_max_per_epoch_activation_churn_limit_gloas")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_per_epoch_activation_churn_limit_gloas: u64,

    #[serde(default = "default_max_transactions_bytes_per_inclusion_list")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_transactions_bytes_per_inclusion_list: u64,
    #[serde(default = "default_max_request_inclusion_list")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_inclusion_list: u64,
    #[serde(default = "default_min_slots_for_inclusion_lists_requests")]
    #[serde(with = "serde_utils::quoted_u64")]
    min_slots_for_inclusion_lists_requests: u64,
    #[serde(default = "default_max_request_payloads")]
    #[serde(with = "serde_utils::quoted_u64")]
    max_request_payloads: u64,
    #[serde(default = "GasLimitSchedule::default")]
    #[serde(skip_serializing_if = "GasLimitSchedule::skip_serializing")]
    pub gas_limit_schedule: GasLimitSchedule,
}

fn default_bellatrix_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

fn default_capella_fork_version() -> [u8; 4] {
    [0xff, 0xff, 0xff, 0xff]
}

fn default_deneb_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

fn default_electra_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

fn default_fulu_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

fn default_gloas_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

fn default_heze_fork_version() -> [u8; 4] {
    // This value shouldn't be used.
    [0xff, 0xff, 0xff, 0xff]
}

/// Placeholder value: 2^256-2^10 (115792089237316195423570985008687907853269984665640564039457584007913129638912).
///
/// Taken from https://github.com/ethereum/consensus-specs/blob/d5e4828aecafaf1c57ef67a5f23c4ae7b08c5137/configs/mainnet.yaml#L15-L16
const fn default_terminal_total_difficulty() -> Uint256 {
    Uint256::from_limbs([
        18446744073709550592,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ])
}

fn default_terminal_block_hash() -> ExecutionBlockHash {
    ExecutionBlockHash::zero()
}

fn default_terminal_block_hash_activation_epoch() -> Epoch {
    Epoch::new(u64::MAX)
}

fn default_subnets_per_node() -> u8 {
    2u8
}

const fn default_epochs_per_subnet_subscription() -> u64 {
    256
}

const fn default_attestation_subnet_count() -> u64 {
    64
}

const fn default_attestation_subnet_extra_bits() -> u8 {
    0
}

/// Compute attestation_subnet_prefix_bits dynamically as:
/// ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS
fn compute_attestation_subnet_prefix_bits(
    attestation_subnet_count: u64,
    attestation_subnet_extra_bits: u8,
) -> u8 {
    let default_attestation_subnet_prefix_bits = 6u8;

    // ceillog2() = next_power_of_two().ilog2()
    // casting to u8 is fine given ilog2(u64::MAX) = 63
    let min_bits_needed = attestation_subnet_count
        .checked_next_power_of_two()
        .and_then(|x| x.checked_ilog2())
        .unwrap_or(default_attestation_subnet_prefix_bits as u32) as u8;

    min_bits_needed
        .safe_add(attestation_subnet_extra_bits)
        .unwrap_or(default_attestation_subnet_prefix_bits)
}

const fn default_max_per_epoch_activation_churn_limit() -> u64 {
    8
}

const fn default_confirmation_byzantine_threshold() -> u64 {
    25
}

const fn default_gas_limit_adjustment_factor() -> u64 {
    1024
}

const fn default_max_payload_size() -> u64 {
    10485760
}

const fn default_min_epochs_for_block_requests() -> u64 {
    33024
}

const fn default_ttfb_timeout() -> u64 {
    5
}

const fn default_resp_timeout() -> u64 {
    10
}

const fn default_message_domain_invalid_snappy() -> [u8; 4] {
    [0, 0, 0, 0]
}

const fn default_message_domain_valid_snappy() -> [u8; 4] {
    [1, 0, 0, 0]
}

const fn default_max_request_blocks() -> u64 {
    1024
}

const fn default_max_request_blocks_deneb() -> u64 {
    128
}

const fn default_max_request_blob_sidecars() -> u64 {
    768
}

const fn default_max_request_data_column_sidecars() -> u64 {
    16384
}

const fn default_min_epochs_for_blob_sidecars_requests() -> u64 {
    4096
}

const fn default_blob_sidecar_subnet_count() -> u64 {
    6
}

/// Its important to keep this consistent with the deneb preset value for
/// `MAX_BLOBS_PER_BLOCK` else we might run into consensus issues.
const fn default_max_blobs_per_block() -> u64 {
    6
}

const fn default_blob_sidecar_subnet_count_electra() -> u64 {
    9
}

const fn default_max_request_blob_sidecars_electra() -> u64 {
    1152
}

const fn default_min_per_epoch_churn_limit_electra() -> u64 {
    128_000_000_000
}

const fn default_max_per_epoch_activation_exit_churn_limit() -> u64 {
    256_000_000_000
}

const fn default_max_blobs_per_block_electra() -> u64 {
    9
}

const fn default_attestation_propagation_slot_range() -> u64 {
    32
}

const fn default_maximum_gossip_clock_disparity() -> u64 {
    500
}

const fn default_custody_requirement() -> u64 {
    4
}

const fn default_data_column_sidecar_subnet_count() -> u64 {
    128
}

const fn default_number_of_custody_groups() -> u64 {
    128
}

const fn default_samples_per_slot() -> u64 {
    8
}

const fn default_validator_custody_requirement() -> u64 {
    8
}

const fn default_balance_per_additional_custody_group() -> u64 {
    32000000000
}

const fn default_min_epochs_for_data_column_sidecars_requests() -> u64 {
    4096
}

const fn default_min_blob_data_retention_ms() -> u64 {
    1572864000
}

const fn default_proposer_reorg_cutoff_bps() -> u64 {
    1667
}

const fn default_attestation_due_bps() -> u64 {
    3333
}

const fn default_attestation_due_bps_gloas() -> u64 {
    2500
}

const fn default_payload_due_bps() -> u64 {
    5000
}

const fn default_payload_attestation_due_bps() -> u64 {
    7500
}

const fn default_aggregate_due_bps() -> u64 {
    6667
}

const fn default_aggregate_due_bps_gloas() -> u64 {
    5000
}

const fn default_inclusion_list_due_bps() -> u64 {
    7500
}

const fn default_sync_message_due_bps() -> u64 {
    3333
}

const fn default_sync_message_due_bps_gloas() -> u64 {
    2500
}

const fn default_contribution_due_bps() -> u64 {
    6667
}

const fn default_contribution_due_bps_gloas() -> u64 {
    5000
}

const fn default_min_builder_withdrawability_delay() -> u64 {
    64
}

const fn default_churn_limit_quotient_gloas() -> u64 {
    32_768
}

const fn default_consolidation_churn_limit_quotient() -> u64 {
    65_536
}

const fn default_max_per_epoch_activation_churn_limit_gloas() -> u64 {
    256_000_000_000
}

const fn default_reorg_head_weight_threshold() -> u64 {
    20
}

const fn default_reorg_parent_weight_threshold() -> u64 {
    160
}

const fn default_reorg_max_epochs_since_finalization() -> u64 {
    2
}

const fn default_max_transactions_bytes_per_inclusion_list() -> u64 {
    8192
}

const fn default_max_request_inclusion_list() -> u64 {
    16
}

const fn default_min_slots_for_inclusion_lists_requests() -> u64 {
    1
}

fn max_blocks_by_root_request_common(max_request_blocks: u64) -> usize {
    let max_request_blocks = max_request_blocks as usize;
    RuntimeVariableList::<Hash256>::new(
        vec![Hash256::zero(); max_request_blocks],
        max_request_blocks,
    )
    .expect("creating a RuntimeVariableList of size `max_request_blocks` should succeed")
    .as_ssz_bytes()
    .len()
}

// Simplified function which precomputes the size of a `List` of `BlobIdentifiers`.
pub(crate) fn max_blobs_by_root_request_common(max_request_blob_sidecars: u64) -> usize {
    // BlobIdentifier is a fixed-size struct with two fields:
    // - block_root: Hash256 (32 bytes)
    // - index: u64 (8 bytes)
    // Total per element: 32 + 8 = 40 bytes
    // Since BlobIdentifier is fixed-size, the outer List does not add any byte overhead.
    let blob_identifier_ssz_size = 40_usize;

    (max_request_blob_sidecars as usize)
        .safe_mul(blob_identifier_ssz_size)
        .expect("should not overflow")
}

// Simplified function which precomputes the size of a `List` of `DataColumnIdentifiers`.
pub(crate) fn max_data_columns_by_root_request_common<E: EthSpec>(
    max_request_blocks: u64,
) -> usize {
    // DataColumnsByRootIdentifier is a variable-size struct with two fields:
    // - block_root: Hash256 (32 bytes)
    // - columns: List<ColumnIndex, NumberOfColumns> (4 byte offset + n × 8 bytes)
    // Since DataColumnsByRootIdentifier is variable-size, the outer List adds a
    // 4-byte offset per element.
    // Total per element: 4 (outer offset) + 32 (block_root) + 4 (columns offset) + n × 8
    let column_index_ssz_size = 8_usize;
    let ssz_fixed_size = 40_usize;

    let data_columns_by_root_identifier_ssz_size = column_index_ssz_size
        .safe_mul(E::number_of_columns())
        .and_then(|b| b.safe_add(ssz_fixed_size))
        .expect("should not overflow");

    (max_request_blocks as usize)
        .safe_mul(data_columns_by_root_identifier_ssz_size)
        .expect("should not overflow")
}

fn default_max_blocks_by_root_request() -> usize {
    max_blocks_by_root_request_common(default_max_request_blocks())
}

fn default_max_blocks_by_root_request_deneb() -> usize {
    max_blocks_by_root_request_common(default_max_request_blocks_deneb())
}

fn default_max_blobs_by_root_request() -> usize {
    max_blobs_by_root_request_common(default_max_request_blob_sidecars())
}

fn default_data_columns_by_root_request() -> usize {
    max_data_columns_by_root_request_common::<MainnetEthSpec>(default_max_request_blocks_deneb())
}

fn default_max_payload_envelopes_by_root_request() -> usize {
    max_blocks_by_root_request_common(default_max_request_payloads())
}

fn default_max_request_payloads() -> u64 {
    128
}

impl Default for Config {
    fn default() -> Self {
        let chain_spec = MainnetEthSpec::default_spec();
        Config::from_chain_spec::<MainnetEthSpec>(&chain_spec)
    }
}

/// Util function to serialize a `None` fork epoch value
/// as `Epoch::max_value()`.
fn serialize_fork_epoch<S>(val: &Option<MaybeQuoted<Epoch>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        None => MaybeQuoted {
            value: Epoch::max_value(),
        }
        .serialize(s),
        Some(epoch) => epoch.serialize(s),
    }
}

/// Util function to deserialize a u64::max() fork epoch as `None`.
fn deserialize_fork_epoch<'de, D>(deserializer: D) -> Result<Option<MaybeQuoted<Epoch>>, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded: Option<MaybeQuoted<Epoch>> = serde::de::Deserialize::deserialize(deserializer)?;
    if let Some(fork_epoch) = decoded
        && fork_epoch.value != Epoch::max_value()
    {
        return Ok(Some(fork_epoch));
    }
    Ok(None)
}

impl Config {
    /// Maps `self` to an identifier for an `EthSpec` instance.
    ///
    /// Returns `None` if there is no match.
    pub fn eth_spec_id(&self) -> Option<EthSpecId> {
        match self.preset_base.as_str() {
            "minimal" => Some(EthSpecId::Minimal),
            "mainnet" => Some(EthSpecId::Mainnet),
            "gnosis" => Some(EthSpecId::Gnosis),
            _ => None,
        }
    }

    pub fn from_chain_spec<E: EthSpec>(spec: &ChainSpec) -> Self {
        Self {
            config_name: spec.config_name.clone(),
            preset_base: E::spec_name().to_string(),

            terminal_total_difficulty: spec.terminal_total_difficulty,
            terminal_block_hash: spec.terminal_block_hash,
            terminal_block_hash_activation_epoch: spec.terminal_block_hash_activation_epoch,

            min_genesis_active_validator_count: spec.min_genesis_active_validator_count,
            min_genesis_time: spec.min_genesis_time,
            genesis_fork_version: spec.genesis_fork_version,
            genesis_delay: spec.genesis_delay,

            altair_fork_version: spec.altair_fork_version,
            altair_fork_epoch: spec
                .altair_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            bellatrix_fork_version: spec.bellatrix_fork_version,
            bellatrix_fork_epoch: spec
                .bellatrix_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            capella_fork_version: spec.capella_fork_version,
            capella_fork_epoch: spec
                .capella_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            deneb_fork_version: spec.deneb_fork_version,
            deneb_fork_epoch: spec
                .deneb_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            electra_fork_version: spec.electra_fork_version,
            electra_fork_epoch: spec
                .electra_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            fulu_fork_version: spec.fulu_fork_version,
            fulu_fork_epoch: spec
                .fulu_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            gloas_fork_version: spec.gloas_fork_version,
            gloas_fork_epoch: spec
                .gloas_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            heze_fork_version: spec.heze_fork_version,
            heze_fork_epoch: spec
                .heze_fork_epoch
                .map(|epoch| MaybeQuoted { value: epoch }),

            seconds_per_slot: Some(MaybeQuoted {
                value: spec.seconds_per_slot,
            }),
            slot_duration_ms: Some(MaybeQuoted {
                value: spec.slot_duration_ms,
            }),
            slot_duration_ms_heze: Some(MaybeQuoted {
                value: spec.slot_duration_ms_heze,
            }),
            seconds_per_eth1_block: spec.seconds_per_eth1_block,
            min_validator_withdrawability_delay: spec.min_validator_withdrawability_delay,
            shard_committee_period: spec.shard_committee_period,
            eth1_follow_distance: spec.eth1_follow_distance,
            subnets_per_node: spec.subnets_per_node,
            epochs_per_subnet_subscription: spec.epochs_per_subnet_subscription,
            attestation_subnet_count: spec.attestation_subnet_count,
            attestation_subnet_extra_bits: spec.attestation_subnet_extra_bits,

            inactivity_score_bias: spec.inactivity_score_bias,
            inactivity_score_recovery_rate: spec.inactivity_score_recovery_rate,
            ejection_balance: spec.ejection_balance,
            churn_limit_quotient: spec.churn_limit_quotient,
            min_per_epoch_churn_limit: spec.min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit: spec.max_per_epoch_activation_churn_limit,

            proposer_score_boost: Some(MaybeQuoted {
                value: spec.proposer_score_boost,
            }),
            reorg_head_weight_threshold: spec.reorg_head_weight_threshold,
            reorg_parent_weight_threshold: spec.reorg_parent_weight_threshold,
            reorg_max_epochs_since_finalization: spec.reorg_max_epochs_since_finalization,

            confirmation_byzantine_threshold: spec.confirmation_byzantine_threshold,

            deposit_chain_id: spec.deposit_chain_id,
            deposit_network_id: spec.deposit_network_id,
            deposit_contract_address: spec.deposit_contract_address,

            gas_limit_adjustment_factor: spec.gas_limit_adjustment_factor,

            max_payload_size: spec.max_payload_size,
            max_request_blocks: spec.max_request_blocks,
            min_epochs_for_block_requests: spec.min_epochs_for_block_requests,
            ttfb_timeout: spec.ttfb_timeout,
            resp_timeout: spec.resp_timeout,
            attestation_propagation_slot_range: spec.attestation_propagation_slot_range,
            maximum_gossip_clock_disparity: spec.maximum_gossip_clock_disparity,
            message_domain_invalid_snappy: spec.message_domain_invalid_snappy,
            message_domain_valid_snappy: spec.message_domain_valid_snappy,
            max_request_blocks_deneb: spec.max_request_blocks_deneb,
            max_request_blob_sidecars: spec.max_request_blob_sidecars,
            max_request_data_column_sidecars: spec.max_request_data_column_sidecars,
            min_epochs_for_blob_sidecars_requests: spec.min_epochs_for_blob_sidecars_requests,
            blob_sidecar_subnet_count: spec.blob_sidecar_subnet_count,
            max_blobs_per_block: spec.max_blobs_per_block,

            min_per_epoch_churn_limit_electra: spec.min_per_epoch_churn_limit_electra,
            max_per_epoch_activation_exit_churn_limit: spec
                .max_per_epoch_activation_exit_churn_limit,
            max_blobs_per_block_electra: spec.max_blobs_per_block_electra,
            blob_sidecar_subnet_count_electra: spec.blob_sidecar_subnet_count_electra,
            max_request_blob_sidecars_electra: spec.max_request_blob_sidecars_electra,

            number_of_custody_groups: spec.number_of_custody_groups,
            data_column_sidecar_subnet_count: spec.data_column_sidecar_subnet_count,
            samples_per_slot: spec.samples_per_slot,
            custody_requirement: spec.custody_requirement,
            blob_schedule: spec.blob_schedule.clone(),
            validator_custody_requirement: spec.validator_custody_requirement,
            balance_per_additional_custody_group: spec.balance_per_additional_custody_group,
            min_epochs_for_data_column_sidecars_requests: spec
                .min_epochs_for_data_column_sidecars_requests,
            min_blob_data_retention_ms: Some(MaybeQuoted {
                value: spec.min_blob_data_retention_ms,
            }),

            proposer_reorg_cutoff_bps: spec.proposer_reorg_cutoff_bps,
            attestation_due_bps: spec.attestation_due_bps,
            attestation_due_bps_gloas: spec.attestation_due_bps_gloas,
            payload_due_bps: spec.payload_due_bps,
            payload_attestation_due_bps: spec.payload_attestation_due_bps,
            aggregate_due_bps: spec.aggregate_due_bps,
            aggregate_due_bps_gloas: spec.aggregate_due_bps_gloas,
            sync_message_due_bps: spec.sync_message_due_bps,
            sync_message_due_bps_gloas: spec.sync_message_due_bps_gloas,
            contribution_due_bps: spec.contribution_due_bps,
            contribution_due_bps_gloas: spec.contribution_due_bps_gloas,
            inclusion_list_due_bps: spec.inclusion_list_due_bps,

            min_builder_withdrawability_delay: spec.min_builder_withdrawability_delay.as_u64(),

            churn_limit_quotient_gloas: spec.churn_limit_quotient_gloas,
            max_transactions_bytes_per_inclusion_list: spec
                .max_transactions_bytes_per_inclusion_list,
            max_request_inclusion_list: spec.max_request_inclusion_list,
            min_slots_for_inclusion_lists_requests: spec.min_slots_for_inclusion_lists_requests,
            max_request_payloads: spec.max_request_payloads,
            consolidation_churn_limit_quotient: spec.consolidation_churn_limit_quotient,
            max_per_epoch_activation_churn_limit_gloas: spec
                .max_per_epoch_activation_churn_limit_gloas,
            gas_limit_schedule: spec.gas_limit_schedule.clone(),
        }
    }

    pub fn from_file(filename: &Path) -> Result<Self, String> {
        let f = File::open(filename)
            .map_err(|e| format!("Error opening spec at {}: {:?}", filename.display(), e))?;
        yaml_serde::from_reader(f)
            .map_err(|e| format!("Error parsing spec at {}: {:?}", filename.display(), e))
    }

    pub fn apply_to_chain_spec<E: EthSpec>(&self, chain_spec: &ChainSpec) -> Option<ChainSpec> {
        // Pattern match here to avoid missing any fields.
        let &Config {
            ref config_name,
            ref preset_base,
            terminal_total_difficulty,
            terminal_block_hash,
            terminal_block_hash_activation_epoch,
            min_genesis_active_validator_count,
            min_genesis_time,
            genesis_fork_version,
            genesis_delay,
            altair_fork_version,
            altair_fork_epoch,
            bellatrix_fork_epoch,
            bellatrix_fork_version,
            capella_fork_epoch,
            capella_fork_version,
            deneb_fork_epoch,
            deneb_fork_version,
            electra_fork_epoch,
            electra_fork_version,
            fulu_fork_epoch,
            fulu_fork_version,
            gloas_fork_version,
            gloas_fork_epoch,
            heze_fork_version,
            heze_fork_epoch,
            seconds_per_slot,
            slot_duration_ms,
            slot_duration_ms_heze,
            seconds_per_eth1_block,
            min_validator_withdrawability_delay,
            shard_committee_period,
            eth1_follow_distance,
            subnets_per_node,
            epochs_per_subnet_subscription,
            attestation_subnet_count,
            attestation_subnet_extra_bits,
            inactivity_score_bias,
            inactivity_score_recovery_rate,
            ejection_balance,
            min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit,
            churn_limit_quotient,
            proposer_score_boost,
            reorg_head_weight_threshold,
            reorg_parent_weight_threshold,
            reorg_max_epochs_since_finalization,
            deposit_chain_id,
            deposit_network_id,
            deposit_contract_address,
            gas_limit_adjustment_factor,
            max_payload_size,
            min_epochs_for_block_requests,
            ttfb_timeout,
            resp_timeout,
            message_domain_invalid_snappy,
            message_domain_valid_snappy,
            max_request_blocks,
            attestation_propagation_slot_range,
            maximum_gossip_clock_disparity,
            max_request_blocks_deneb,
            max_request_blob_sidecars,
            max_request_data_column_sidecars,
            min_epochs_for_blob_sidecars_requests,
            blob_sidecar_subnet_count,
            max_blobs_per_block,

            min_per_epoch_churn_limit_electra,
            max_per_epoch_activation_exit_churn_limit,
            max_blobs_per_block_electra,
            blob_sidecar_subnet_count_electra,
            max_request_blob_sidecars_electra,
            number_of_custody_groups,
            data_column_sidecar_subnet_count,
            samples_per_slot,
            custody_requirement,
            ref blob_schedule,
            validator_custody_requirement,
            balance_per_additional_custody_group,
            min_epochs_for_data_column_sidecars_requests,
            min_blob_data_retention_ms,
            proposer_reorg_cutoff_bps,
            attestation_due_bps,
            attestation_due_bps_gloas,
            payload_due_bps,
            payload_attestation_due_bps,
            aggregate_due_bps,
            aggregate_due_bps_gloas,
            sync_message_due_bps,
            sync_message_due_bps_gloas,
            contribution_due_bps,
            contribution_due_bps_gloas,
            confirmation_byzantine_threshold,
            inclusion_list_due_bps,
            min_builder_withdrawability_delay,
            churn_limit_quotient_gloas,
            consolidation_churn_limit_quotient,
            max_per_epoch_activation_churn_limit_gloas,
            max_transactions_bytes_per_inclusion_list,
            max_request_inclusion_list,
            min_slots_for_inclusion_lists_requests,
            max_request_payloads,
            ref gas_limit_schedule,
        } = self;

        if preset_base != E::spec_name().to_string().as_str() {
            return None;
        }

        // Fail if seconds_per_slot and slot_duration_ms are both set but are inconsistent.
        if let (Some(seconds_per_slot), Some(slot_duration_ms)) =
            (seconds_per_slot, slot_duration_ms)
            && seconds_per_slot.value.saturating_mul(1000) != slot_duration_ms.value
        {
            return None;
        }

        let slot_duration_ms = slot_duration_ms
            .map(|q| q.value)
            .or_else(|| seconds_per_slot.map(|q| q.value.saturating_mul(1000)))?;
        let seconds_per_slot = seconds_per_slot
            .map(|q| q.value)
            .or_else(|| slot_duration_ms.checked_div(1000))?;
        let min_blob_data_retention_ms = match min_blob_data_retention_ms {
            Some(q) => q.value,
            None => min_epochs_for_data_column_sidecars_requests
                .checked_mul(E::slots_per_epoch())?
                .checked_mul(slot_duration_ms)?,
        };
        // Networks that do not set it keep their slot duration at the fork.
        let slot_duration_ms_heze = match slot_duration_ms_heze {
            Some(q)
                if q.value == 0
                    || q.value % 1000 != 0
                    || q.value.checked_mul(BASIS_POINTS).is_none() =>
            {
                error!(
                    slot_duration_ms_heze = q.value,
                    "Invalid SLOT_DURATION_MS_HEZE"
                );
                return None;
            }
            Some(q) => q.value,
            None => slot_duration_ms,
        };

        // Entries must be at or after the Gloas fork epoch and must not share an epoch.
        let min_gas_limit_schedule_epoch = gloas_fork_epoch
            .map(|q| q.value)
            .unwrap_or(chain_spec.far_future_epoch);
        if let Some(entry) = gas_limit_schedule
            .as_vec()
            .iter()
            .find(|entry| entry.epoch < min_gas_limit_schedule_epoch)
        {
            error!(
                epoch = %entry.epoch,
                gloas_fork_epoch = %min_gas_limit_schedule_epoch,
                "GAS_LIMIT_SCHEDULE entry is before the Gloas fork epoch"
            );
            return None;
        }
        if let Some([entry, _]) = gas_limit_schedule
            .as_vec()
            .windows(2)
            .find(|pair| matches!(pair, [a, b] if a.epoch == b.epoch))
        {
            error!(
                epoch = %entry.epoch,
                "GAS_LIMIT_SCHEDULE has multiple entries for the same epoch"
            );
            return None;
        }

        let spec = ChainSpec {
            config_name: config_name.clone(),
            min_genesis_active_validator_count,
            min_genesis_time,
            genesis_fork_version,
            genesis_delay,
            altair_fork_version,
            altair_fork_epoch: altair_fork_epoch.map(|q| q.value),
            bellatrix_fork_epoch: bellatrix_fork_epoch.map(|q| q.value),
            bellatrix_fork_version,
            capella_fork_epoch: capella_fork_epoch.map(|q| q.value),
            capella_fork_version,
            deneb_fork_epoch: deneb_fork_epoch.map(|q| q.value),
            deneb_fork_version,
            electra_fork_epoch: electra_fork_epoch.map(|q| q.value),
            electra_fork_version,
            fulu_fork_epoch: fulu_fork_epoch.map(|q| q.value),
            fulu_fork_version,
            gloas_fork_version,
            gloas_fork_epoch: gloas_fork_epoch.map(|q| q.value),
            heze_fork_version,
            heze_fork_epoch: heze_fork_epoch.map(|q| q.value),
            seconds_per_slot,
            slot_duration_ms,
            slot_duration_ms_heze,
            seconds_per_eth1_block,
            min_validator_withdrawability_delay,
            shard_committee_period,
            eth1_follow_distance,
            subnets_per_node,
            epochs_per_subnet_subscription,
            attestation_subnet_count,
            attestation_subnet_extra_bits,
            inactivity_score_bias,
            inactivity_score_recovery_rate,
            ejection_balance,
            min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit,
            churn_limit_quotient,
            proposer_score_boost: proposer_score_boost
                .map(|q| q.value)
                .unwrap_or(chain_spec.proposer_score_boost),
            confirmation_byzantine_threshold,
            reorg_head_weight_threshold,
            reorg_parent_weight_threshold,
            reorg_max_epochs_since_finalization,
            deposit_chain_id,
            deposit_network_id,
            deposit_contract_address,
            gas_limit_adjustment_factor,
            terminal_total_difficulty,
            terminal_block_hash,
            terminal_block_hash_activation_epoch,
            max_payload_size,
            min_epochs_for_block_requests,
            ttfb_timeout,
            resp_timeout,
            message_domain_invalid_snappy,
            message_domain_valid_snappy,
            max_request_blocks,
            attestation_propagation_slot_range,
            maximum_gossip_clock_disparity,
            max_request_blocks_deneb,
            max_request_blob_sidecars,
            max_request_data_column_sidecars,
            min_epochs_for_blob_sidecars_requests,
            blob_sidecar_subnet_count,
            max_blobs_per_block,

            min_per_epoch_churn_limit_electra,
            max_per_epoch_activation_exit_churn_limit,
            max_blobs_per_block_electra,
            max_request_blob_sidecars_electra,
            blob_sidecar_subnet_count_electra,

            number_of_custody_groups,
            data_column_sidecar_subnet_count,
            samples_per_slot,
            custody_requirement,
            blob_schedule: blob_schedule.clone(),
            validator_custody_requirement,
            balance_per_additional_custody_group,
            min_epochs_for_data_column_sidecars_requests,
            min_blob_data_retention_ms,

            proposer_reorg_cutoff_bps,
            attestation_due_bps,
            attestation_due_bps_gloas,
            payload_due_bps,
            payload_attestation_due_bps,
            aggregate_due_bps,
            aggregate_due_bps_gloas,
            sync_message_due_bps,
            sync_message_due_bps_gloas,
            contribution_due_bps,
            contribution_due_bps_gloas,
            inclusion_list_due_bps,

            min_builder_withdrawability_delay: Epoch::new(min_builder_withdrawability_delay),

            churn_limit_quotient_gloas,
            consolidation_churn_limit_quotient,
            max_per_epoch_activation_churn_limit_gloas,
            gas_limit_schedule: gas_limit_schedule.clone(),

            max_transactions_bytes_per_inclusion_list,
            max_request_inclusion_list,
            min_slots_for_inclusion_lists_requests,
            max_request_payloads,

            ..chain_spec.clone()
        };
        Some(spec.compute_derived_values::<E>())
    }
}

/// A simple wrapper to permit the in-line use of `?`.
fn option_wrapper<F, T>(f: F) -> Option<T>
where
    F: Fn() -> Option<T>,
{
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

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
            assert_eq!(&domain1.as_slice()[0..4], &int_to_bytes4(raw_domain)[..]);
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
        test_domain(Domain::BeaconBuilder, spec.domain_beacon_builder, &spec);
        test_domain(Domain::PTCAttester, spec.domain_ptc_attester, &spec);
        test_domain(Domain::ExecutionProof, spec.domain_execution_proof, &spec);
        test_domain(
            Domain::InclusionListCommittee,
            spec.domain_inclusion_list_committee,
            &spec,
        );
        test_domain(
            Domain::ProposerPreferences,
            spec.domain_proposer_preferences,
            &spec,
        );
        test_domain(Domain::BuilderDeposit, spec.domain_builder_deposit, &spec);

        // The builder domain index is zero
        let builder_domain_pre_mask = [0; 4];
        test_domain(
            Domain::ApplicationMask(ApplicationDomain::Builder),
            apply_bit_mask(builder_domain_pre_mask, &spec),
            &spec,
        );

        test_domain(
            Domain::BlsToExecutionChange,
            spec.domain_bls_to_execution_change,
            &spec,
        );
    }

    #[test]
    fn test_request_auth_domain() {
        let spec = ChainSpec::mainnet();
        let domain = spec.get_request_auth_domain();
        // DOMAIN_REQUEST_AUTH = 0x0B000001 (builder-specs #165), little-endian in the first 4 bytes.
        assert_eq!(&domain.as_slice()[0..4], &[0x0B, 0x00, 0x00, 0x01]);
        // Same out-of-protocol computation as the builder application domain (genesis fork version,
        // zero root), so only the domain-type prefix differs.
        let builder = spec.get_builder_application_domain();
        assert_eq!(&domain.as_slice()[4..], &builder.as_slice()[4..]);
        assert_ne!(&domain.as_slice()[0..4], &builder.as_slice()[0..4]);
    }

    fn apply_bit_mask(domain_bytes: [u8; 4], spec: &ChainSpec) -> u32 {
        let mut domain = [0; 4];
        let mask_bytes = int_to_bytes4(spec.domain_application_mask);

        // Apply application bit mask
        for (i, (domain_byte, mask_byte)) in domain_bytes.iter().zip(mask_bytes.iter()).enumerate()
        {
            domain[i] = domain_byte | mask_byte;
        }

        u32::from_le_bytes(domain)
    }

    // Test that `fork_name_at_epoch` and `fork_epoch` are consistent.
    #[test]
    fn fork_name_at_epoch_consistency() {
        let spec = ChainSpec::mainnet();

        for fork_name in ForkName::list_all() {
            if let Some(fork_epoch) = spec.fork_epoch(fork_name) {
                assert_eq!(spec.fork_name_at_epoch(fork_epoch), fork_name);
            }
        }
    }

    // Test that `next_fork_epoch` is consistent with the other functions.
    #[test]
    fn next_fork_epoch_consistency() {
        type E = MainnetEthSpec;
        let spec = ChainSpec::mainnet();

        let mut last_fork_slot = Slot::new(0);

        for (_, fork) in ForkName::list_all().into_iter().tuple_windows() {
            if let Some(fork_epoch) = spec.fork_epoch(fork) {
                last_fork_slot = fork_epoch.start_slot(E::slots_per_epoch());

                // Fork is activated at non-zero epoch: check that `next_fork_epoch` returns
                // the correct result.
                if let Ok(prior_slot) = last_fork_slot.safe_sub(1) {
                    let (next_fork, next_fork_epoch) =
                        spec.next_fork_epoch::<E>(prior_slot).unwrap();
                    assert_eq!(fork, next_fork);
                    assert_eq!(spec.fork_epoch(fork).unwrap(), next_fork_epoch);
                }
            } else {
                // Fork is not activated, check that `next_fork_epoch` returns `None`.
                assert_eq!(spec.next_fork_epoch::<E>(last_fork_slot), None);
            }
        }
    }

    #[test]
    fn enr_fork_id_next_fork_with_bpo() {
        type E = MainnetEthSpec;
        let far_future = Epoch::new(u64::MAX);
        let slot = Epoch::new(10).start_slot(E::slots_per_epoch());

        let cases = [
            (
                ForkName::Fulu,
                None,
                Some(20),
                Some(30),
                ForkName::Fulu,
                Epoch::new(20),
            ),
            (
                ForkName::Fulu,
                None,
                Some(20),
                Some(20),
                ForkName::Gloas,
                Epoch::new(20),
            ),
            (
                ForkName::Fulu,
                None,
                Some(30),
                Some(20),
                ForkName::Gloas,
                Epoch::new(20),
            ),
            (
                ForkName::Fulu,
                None,
                Some(20),
                None,
                ForkName::Fulu,
                Epoch::new(20),
            ),
            (
                ForkName::Fulu,
                None,
                Some(5),
                Some(30),
                ForkName::Gloas,
                Epoch::new(30),
            ),
            (ForkName::Fulu, None, None, None, ForkName::Fulu, far_future),
            (
                ForkName::Fulu,
                None,
                None,
                Some(u64::MAX),
                ForkName::Fulu,
                far_future,
            ),
            (
                ForkName::Electra,
                Some(20),
                Some(30),
                None,
                ForkName::Fulu,
                Epoch::new(20),
            ),
        ];

        for (genesis_fork, fulu_epoch, bpo_epoch, gloas_epoch, expected_fork, expected_epoch) in
            cases
        {
            let mut spec = genesis_fork.make_genesis_spec(E::default_spec());
            if let Some(fulu_epoch) = fulu_epoch {
                spec.fulu_fork_epoch = Some(Epoch::new(fulu_epoch));
            }
            spec.gloas_fork_epoch = gloas_epoch.map(Epoch::new);
            spec.blob_schedule = BlobSchedule::new(
                bpo_epoch
                    .into_iter()
                    .map(|epoch| BlobParameters {
                        epoch: Epoch::new(epoch),
                        max_blobs_per_block: 21,
                    })
                    .collect(),
            );

            let enr_fork_id = spec.enr_fork_id::<E>(slot, Hash256::zero());
            assert_eq!(
                enr_fork_id.next_fork_version,
                spec.fork_version_for_name(expected_fork),
                "bpo {bpo_epoch:?}, gloas {gloas_epoch:?}"
            );
            assert_eq!(
                enr_fork_id.next_fork_epoch, expected_epoch,
                "bpo {bpo_epoch:?}, gloas {gloas_epoch:?}"
            );
        }
    }

    #[test]
    fn test_compute_min_bits_for_n_values_edge_cases() {
        assert_eq!(compute_attestation_subnet_prefix_bits(64, 0), 6);
        assert_eq!(compute_attestation_subnet_prefix_bits(65, 0), 7);
        assert_eq!(compute_attestation_subnet_prefix_bits(0, 1), 1);
    }
}

#[cfg(test)]
mod yaml_tests {
    use super::*;
    use crate::core::MinimalEthSpec;
    use paste::paste;
    use std::collections::BTreeSet;
    use std::env;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[test]
    fn minimal_round_trip() {
        // create temp file
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = File::options()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let minimal_spec = ChainSpec::minimal();

        let yamlconfig = Config::from_chain_spec::<MinimalEthSpec>(&minimal_spec);
        // write fresh minimal config to file
        yaml_serde::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = File::options()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        // deserialize minimal config from file
        let from: Config = yaml_serde::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn mainnet_round_trip() {
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = File::options()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let mainnet_spec = ChainSpec::mainnet();
        let yamlconfig = Config::from_chain_spec::<MainnetEthSpec>(&mainnet_spec);
        yaml_serde::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = File::options()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: Config = yaml_serde::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }

    #[test]
    fn slot_duration_fallback_both_fields() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.seconds_per_slot = Some(MaybeQuoted { value: 12 });
        config.slot_duration_ms = Some(MaybeQuoted { value: 12000 });
        let spec = config
            .apply_to_chain_spec::<MainnetEthSpec>(&mainnet)
            .unwrap();
        assert_eq!(spec.seconds_per_slot, 12);
        assert_eq!(spec.slot_duration_ms, 12000);
    }

    #[test]
    fn slot_duration_fallback_both_fields_inconsistent() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.seconds_per_slot = Some(MaybeQuoted { value: 10 });
        config.slot_duration_ms = Some(MaybeQuoted { value: 12000 });
        assert_eq!(config.apply_to_chain_spec::<MainnetEthSpec>(&mainnet), None);
    }

    #[test]
    fn slot_duration_fallback_seconds_only() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.seconds_per_slot = Some(MaybeQuoted { value: 12 });
        config.slot_duration_ms = None;
        let spec = config
            .apply_to_chain_spec::<MainnetEthSpec>(&mainnet)
            .unwrap();
        assert_eq!(spec.seconds_per_slot, 12);
        assert_eq!(spec.slot_duration_ms, 12000);
    }

    #[test]
    fn slot_duration_fallback_ms_only() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.seconds_per_slot = None;
        config.slot_duration_ms = Some(MaybeQuoted { value: 12000 });
        let spec = config
            .apply_to_chain_spec::<MainnetEthSpec>(&mainnet)
            .unwrap();
        assert_eq!(spec.seconds_per_slot, 12);
        assert_eq!(spec.slot_duration_ms, 12000);
    }

    #[test]
    fn slot_duration_fallback_neither() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.seconds_per_slot = None;
        config.slot_duration_ms = None;
        assert!(
            config
                .apply_to_chain_spec::<MainnetEthSpec>(&mainnet)
                .is_none()
        );
    }

    #[test]
    fn blob_schedule_max_blobs_per_block() {
        let spec_contents = r#"
        PRESET_BASE: 'mainnet'
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 384
        MIN_GENESIS_TIME: 1748264340
        GENESIS_FORK_VERSION: 0x10355025
        GENESIS_DELAY: 60
        SECONDS_PER_SLOT: 12
        SLOT_DURATION_MS: 12000
        SECONDS_PER_ETH1_BLOCK: 12
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256
        SHARD_COMMITTEE_PERIOD: 256
        ETH1_FOLLOW_DISTANCE: 2048
        INACTIVITY_SCORE_BIAS: 4
        INACTIVITY_SCORE_RECOVERY_RATE: 16
        EJECTION_BALANCE: 16000000000
        MIN_PER_EPOCH_CHURN_LIMIT: 4
        CHURN_LIMIT_QUOTIENT: 65536
        MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8
        PROPOSER_SCORE_BOOST: 40
        REORG_HEAD_WEIGHT_THRESHOLD: 20
        REORG_PARENT_WEIGHT_THRESHOLD: 160
        REORG_MAX_EPOCHS_SINCE_FINALIZATION: 2
        EPOCHS_PER_SUBNET_SUBSCRIPTION: 256
        ATTESTATION_SUBNET_COUNT: 64
        ATTESTATION_SUBNET_EXTRA_BITS: 0
        DEPOSIT_CHAIN_ID: 7042643276
        DEPOSIT_NETWORK_ID: 7042643276
        DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa

        ALTAIR_FORK_VERSION: 0x20355025
        ALTAIR_FORK_EPOCH: 0
        BELLATRIX_FORK_VERSION: 0x30355025
        BELLATRIX_FORK_EPOCH: 0
        CAPELLA_FORK_VERSION: 0x40355025
        CAPELLA_FORK_EPOCH: 0
        DENEB_FORK_VERSION: 0x50355025
        DENEB_FORK_EPOCH: 64
        ELECTRA_FORK_VERSION: 0x60355025
        ELECTRA_FORK_EPOCH: 128
        FULU_FORK_VERSION: 0x70355025
        FULU_FORK_EPOCH: 256
        GLOAS_FORK_VERSION: 0x80355025
        GLOAS_FORK_EPOCH: 512
        BLOB_SCHEDULE:
          - EPOCH: 512
            MAX_BLOBS_PER_BLOCK: 12
          - EPOCH: 768
            MAX_BLOBS_PER_BLOCK: 15
          - EPOCH: 1024
            MAX_BLOBS_PER_BLOCK: 18
          - EPOCH: 1280
            MAX_BLOBS_PER_BLOCK: 9
          - EPOCH: 1584
            MAX_BLOBS_PER_BLOCK: 20
        "#;
        let config: Config =
            yaml_serde::from_str(spec_contents).expect("error while deserializing");
        let spec =
            ChainSpec::from_config::<MainnetEthSpec>(&config).expect("error while creating spec");

        // test out max_blobs_per_block(epoch)
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(64)),
            default_max_blobs_per_block()
        );
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(127)),
            default_max_blobs_per_block()
        );
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(128)),
            default_max_blobs_per_block_electra()
        );
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(255)),
            default_max_blobs_per_block_electra()
        );
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(256)),
            default_max_blobs_per_block_electra()
        );
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(511)),
            default_max_blobs_per_block_electra()
        );
        assert_eq!(spec.max_blobs_per_block(Epoch::new(512)), 12);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(767)), 12);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(768)), 15);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1023)), 15);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1024)), 18);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1279)), 18);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1280)), 9);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1583)), 9);
        assert_eq!(spec.max_blobs_per_block(Epoch::new(1584)), 20);
        assert_eq!(
            spec.max_blobs_per_block(Epoch::new(18446744073709551615)),
            20
        );
        assert_eq!(
            spec.compute_max_data_column_sidecar_size_gloas::<MainnetEthSpec>(),
            41976
        );
        assert_eq!(
            spec.compute_max_partial_data_column_sidecar_size_gloas::<MainnetEthSpec>(),
            41935
        );

        // blob schedule is reverse sorted by epoch
        assert_eq!(
            config.blob_schedule.as_vec(),
            &vec![
                BlobParameters {
                    epoch: Epoch::new(1584),
                    max_blobs_per_block: 20
                },
                BlobParameters {
                    epoch: Epoch::new(1280),
                    max_blobs_per_block: 9
                },
                BlobParameters {
                    epoch: Epoch::new(1024),
                    max_blobs_per_block: 18
                },
                BlobParameters {
                    epoch: Epoch::new(768),
                    max_blobs_per_block: 15
                },
                BlobParameters {
                    epoch: Epoch::new(512),
                    max_blobs_per_block: 12
                },
            ]
        );

        // test max_blobs_per_block_within_fork
        assert_eq!(
            spec.max_blobs_per_block_within_fork(ForkName::Deneb),
            default_max_blobs_per_block()
        );
        assert_eq!(
            spec.max_blobs_per_block_within_fork(ForkName::Electra),
            default_max_blobs_per_block_electra()
        );
        assert_eq!(spec.max_blobs_per_block_within_fork(ForkName::Fulu), 20);

        // Check that serialization is in ascending order
        let yaml = yaml_serde::to_string(&spec.blob_schedule).expect("should serialize");

        // Deserialize back to Vec<BlobParameters> to check order
        let deserialized: Vec<BlobParameters> =
            yaml_serde::from_str(&yaml).expect("should deserialize");

        // Should be in ascending order by epoch
        assert!(
            deserialized.iter().map(|bp| bp.epoch.as_u64()).is_sorted(),
            "BlobSchedule should serialize in ascending order by epoch"
        );
    }

    #[test]
    fn gas_limit_schedule() {
        let spec_contents = r#"
        PRESET_BASE: 'mainnet'
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 384
        MIN_GENESIS_TIME: 1748264340
        GENESIS_FORK_VERSION: 0x10355025
        GENESIS_DELAY: 60
        SECONDS_PER_SLOT: 12
        SLOT_DURATION_MS: 12000
        SECONDS_PER_ETH1_BLOCK: 12
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256
        SHARD_COMMITTEE_PERIOD: 256
        ETH1_FOLLOW_DISTANCE: 2048
        INACTIVITY_SCORE_BIAS: 4
        INACTIVITY_SCORE_RECOVERY_RATE: 16
        EJECTION_BALANCE: 16000000000
        MIN_PER_EPOCH_CHURN_LIMIT: 4
        CHURN_LIMIT_QUOTIENT: 65536
        MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8
        PROPOSER_SCORE_BOOST: 40
        REORG_HEAD_WEIGHT_THRESHOLD: 20
        REORG_PARENT_WEIGHT_THRESHOLD: 160
        REORG_MAX_EPOCHS_SINCE_FINALIZATION: 2
        EPOCHS_PER_SUBNET_SUBSCRIPTION: 256
        ATTESTATION_SUBNET_COUNT: 64
        ATTESTATION_SUBNET_EXTRA_BITS: 0
        DEPOSIT_CHAIN_ID: 7042643276
        DEPOSIT_NETWORK_ID: 7042643276
        DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa

        ALTAIR_FORK_VERSION: 0x20355025
        ALTAIR_FORK_EPOCH: 0
        BELLATRIX_FORK_VERSION: 0x30355025
        BELLATRIX_FORK_EPOCH: 0
        CAPELLA_FORK_VERSION: 0x40355025
        CAPELLA_FORK_EPOCH: 0
        DENEB_FORK_VERSION: 0x50355025
        DENEB_FORK_EPOCH: 0
        ELECTRA_FORK_VERSION: 0x60355025
        ELECTRA_FORK_EPOCH: 0
        FULU_FORK_VERSION: 0x70355025
        FULU_FORK_EPOCH: 0
        GLOAS_FORK_VERSION: 0x80355025
        GLOAS_FORK_EPOCH: 512
        GAS_LIMIT_SCHEDULE:
          - EPOCH: 768
            GAS_LIMIT: 75000000
          - EPOCH: 512
            GAS_LIMIT: 60000000
        "#;
        let config: Config =
            yaml_serde::from_str(spec_contents).expect("error while deserializing");
        let spec =
            ChainSpec::from_config::<MainnetEthSpec>(&config).expect("error while creating spec");

        // The schedule does not apply before the Gloas fork epoch.
        assert_eq!(spec.get_scheduled_gas_limit(Epoch::new(0)), None);
        assert_eq!(spec.get_scheduled_gas_limit(Epoch::new(511)), None);
        assert_eq!(
            spec.get_scheduled_gas_limit(Epoch::new(512)),
            Some(60000000)
        );
        assert_eq!(
            spec.get_scheduled_gas_limit(Epoch::new(767)),
            Some(60000000)
        );
        assert_eq!(
            spec.get_scheduled_gas_limit(Epoch::new(768)),
            Some(75000000)
        );
        assert_eq!(
            spec.get_scheduled_gas_limit(Epoch::new(u64::MAX)),
            Some(75000000)
        );

        // The default gas limit follows the schedule from the fork and is the constant before it.
        assert_eq!(spec.default_gas_limit(Epoch::new(511)), DEFAULT_GAS_LIMIT);
        assert_eq!(spec.default_gas_limit(Epoch::new(512)), 60000000);
        assert_eq!(spec.default_gas_limit(Epoch::new(768)), 75000000);

        // gas limit schedule is reverse sorted by epoch
        assert_eq!(
            config.gas_limit_schedule.as_vec(),
            &vec![
                GasLimitScheduleEntry {
                    epoch: Epoch::new(768),
                    gas_limit: 75000000
                },
                GasLimitScheduleEntry {
                    epoch: Epoch::new(512),
                    gas_limit: 60000000
                },
            ]
        );

        // Check that serialization is in ascending order
        let yaml = yaml_serde::to_string(&spec.gas_limit_schedule).expect("should serialize");
        let deserialized: Vec<GasLimitScheduleEntry> =
            yaml_serde::from_str(&yaml).expect("should deserialize");
        assert!(
            deserialized
                .iter()
                .map(|entry| entry.epoch.as_u64())
                .is_sorted(),
            "GasLimitSchedule should serialize in ascending order by epoch"
        );

        // An empty schedule returns no scheduled gas limit.
        let empty = GasLimitSchedule::default();
        assert_eq!(empty.gas_limit_for_epoch(Epoch::new(u64::MAX)), None);

        // The schedule returns nothing when Gloas is not scheduled.
        let mut no_gloas_spec = spec.clone();
        no_gloas_spec.gloas_fork_epoch = None;
        assert_eq!(no_gloas_spec.get_scheduled_gas_limit(Epoch::new(768)), None);

        // An entry before the Gloas fork epoch is rejected.
        let mut early_entry_config = config.clone();
        early_entry_config.gas_limit_schedule =
            GasLimitSchedule::new(vec![GasLimitScheduleEntry {
                epoch: Epoch::new(511),
                gas_limit: 60000000,
            }]);
        assert!(ChainSpec::from_config::<MainnetEthSpec>(&early_entry_config).is_none());

        // A non-empty schedule is rejected when Gloas is not scheduled.
        let mut no_gloas_config = config.clone();
        no_gloas_config.gloas_fork_epoch = None;
        assert!(ChainSpec::from_config::<MainnetEthSpec>(&no_gloas_config).is_none());

        // Two entries with the same epoch are rejected.
        let mut duplicate_epoch_config = config.clone();
        duplicate_epoch_config.gas_limit_schedule = GasLimitSchedule::new(vec![
            GasLimitScheduleEntry {
                epoch: Epoch::new(512),
                gas_limit: 60000000,
            },
            GasLimitScheduleEntry {
                epoch: Epoch::new(512),
                gas_limit: 75000000,
            },
        ]);
        assert!(ChainSpec::from_config::<MainnetEthSpec>(&duplicate_epoch_config).is_none());
    }

    #[test]
    fn blob_schedule_fork_digest() {
        let spec_contents = r#"
        PRESET_BASE: 'mainnet'
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 384
        MIN_GENESIS_TIME: 1748264340
        GENESIS_FORK_VERSION: 0x10355025
        GENESIS_DELAY: 60
        SECONDS_PER_SLOT: 12
        SLOT_DURATION_MS: 12000
        SECONDS_PER_ETH1_BLOCK: 12
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256
        SHARD_COMMITTEE_PERIOD: 256
        ETH1_FOLLOW_DISTANCE: 2048
        INACTIVITY_SCORE_BIAS: 4
        INACTIVITY_SCORE_RECOVERY_RATE: 16
        EJECTION_BALANCE: 16000000000
        MIN_PER_EPOCH_CHURN_LIMIT: 4
        CHURN_LIMIT_QUOTIENT: 65536
        MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8
        PROPOSER_SCORE_BOOST: 40
        REORG_HEAD_WEIGHT_THRESHOLD: 20
        REORG_PARENT_WEIGHT_THRESHOLD: 160
        REORG_MAX_EPOCHS_SINCE_FINALIZATION: 2
        EPOCHS_PER_SUBNET_SUBSCRIPTION: 256
        ATTESTATION_SUBNET_COUNT: 64
        ATTESTATION_SUBNET_EXTRA_BITS: 0
        DEPOSIT_CHAIN_ID: 7042643276
        DEPOSIT_NETWORK_ID: 7042643276
        DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa

        ALTAIR_FORK_VERSION: 0x20355025
        ALTAIR_FORK_EPOCH: 0
        BELLATRIX_FORK_VERSION: 0x30355025
        BELLATRIX_FORK_EPOCH: 0
        CAPELLA_FORK_VERSION: 0x40355025
        CAPELLA_FORK_EPOCH: 0
        DENEB_FORK_VERSION: 0x50355025
        DENEB_FORK_EPOCH: 0
        ELECTRA_FORK_VERSION: 0x60000000
        ELECTRA_FORK_EPOCH: 9
        FULU_FORK_VERSION: 0x06000000
        FULU_FORK_EPOCH: 100
        BLOB_SCHEDULE:
          - EPOCH: 9
            MAX_BLOBS_PER_BLOCK: 9
          - EPOCH: 100
            MAX_BLOBS_PER_BLOCK: 100
          - EPOCH: 150
            MAX_BLOBS_PER_BLOCK: 175
          - EPOCH: 200
            MAX_BLOBS_PER_BLOCK: 200
          - EPOCH: 250
            MAX_BLOBS_PER_BLOCK: 275
          - EPOCH: 300
            MAX_BLOBS_PER_BLOCK: 300
        "#;
        let config: Config =
            yaml_serde::from_str(spec_contents).expect("error while deserializing");
        let spec =
            ChainSpec::from_config::<MainnetEthSpec>(&config).expect("error while creating spec");

        let genesis_validators_root = Hash256::from_slice(&[0; 32]);

        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(100));
        assert_eq!(digest, [0xdf, 0x67, 0x55, 0x7b]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(101));
        assert_eq!(digest, [0xdf, 0x67, 0x55, 0x7b]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(150));
        assert_eq!(digest, [0x8a, 0xb3, 0x8b, 0x59]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(199));
        assert_eq!(digest, [0x8a, 0xb3, 0x8b, 0x59]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(200));
        assert_eq!(digest, [0xd9, 0xb8, 0x14, 0x38]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(201));
        assert_eq!(digest, [0xd9, 0xb8, 0x14, 0x38]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(250));
        assert_eq!(digest, [0x4e, 0xf3, 0x2a, 0x62]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(299));
        assert_eq!(digest, [0x4e, 0xf3, 0x2a, 0x62]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(300));
        assert_eq!(digest, [0xca, 0x10, 0x0d, 0x64]);
        let digest = spec.compute_fork_digest(genesis_validators_root, Epoch::new(301));
        assert_eq!(digest, [0xca, 0x10, 0x0d, 0x64]);
    }

    #[test]
    fn apply_to_spec() {
        let mut spec = ChainSpec::minimal();
        let yamlconfig = Config::from_chain_spec::<MinimalEthSpec>(&spec);

        // modifying the original spec
        spec.min_genesis_active_validator_count += 1;
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

    #[test]
    fn test_defaults() {
        // Spec yaml string. Fields that serialize/deserialize with a default value are commented out.
        let spec = r#"
        PRESET_BASE: 'mainnet'
        #TERMINAL_TOTAL_DIFFICULTY: 115792089237316195423570985008687907853269984665640564039457584007913129638911
        #TERMINAL_BLOCK_HASH: 0x0000000000000000000000000000000000000000000000000000000000000001
        #TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: 18446744073709551614
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 16384
        MIN_GENESIS_TIME: 1606824000
        GENESIS_FORK_VERSION: 0x00000000
        GENESIS_DELAY: 604800
        ALTAIR_FORK_VERSION: 0x01000000
        ALTAIR_FORK_EPOCH: 74240
        #BELLATRIX_FORK_VERSION: 0x02000000
        #BELLATRIX_FORK_EPOCH: 18446744073709551614
        SHARDING_FORK_VERSION: 0x03000000
        SHARDING_FORK_EPOCH: 18446744073709551615
        SECONDS_PER_SLOT: 12
        SLOT_DURATION_MS: 12000
        SECONDS_PER_ETH1_BLOCK: 14
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256
        SHARD_COMMITTEE_PERIOD: 256
        ETH1_FOLLOW_DISTANCE: 2048
        INACTIVITY_SCORE_BIAS: 4
        INACTIVITY_SCORE_RECOVERY_RATE: 16
        EJECTION_BALANCE: 16000000000
        MIN_PER_EPOCH_CHURN_LIMIT: 4
        MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8
        CHURN_LIMIT_QUOTIENT: 65536
        PROPOSER_SCORE_BOOST: 40
        EPOCHS_PER_SUBNET_SUBSCRIPTION: 256
        ATTESTATION_SUBNET_COUNT: 64
        ATTESTATION_SUBNET_EXTRA_BITS: 0
        DEPOSIT_CHAIN_ID: 1
        DEPOSIT_NETWORK_ID: 1
        DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa
        CUSTODY_REQUIREMENT: 1
        DATA_COLUMN_SIDECAR_SUBNET_COUNT: 128
        SAMPLES_PER_SLOT: 8
        "#;

        let chain_spec: Config = yaml_serde::from_str(spec).unwrap();

        // Asserts that `chain_spec.$name` and `default_$name()` are equal.
        macro_rules! check_default {
            ($name: ident) => {
                paste! {
                    assert_eq!(
                        chain_spec.$name,
                        [<default_ $name>](),
                        "{} does not match default", stringify!($name));
                }
            };
        }

        check_default!(terminal_total_difficulty);
        check_default!(terminal_block_hash);
        check_default!(terminal_block_hash_activation_epoch);
        check_default!(bellatrix_fork_version);
        check_default!(max_payload_size);
        check_default!(min_epochs_for_block_requests);
        check_default!(ttfb_timeout);
        check_default!(resp_timeout);
        check_default!(message_domain_invalid_snappy);
        check_default!(message_domain_valid_snappy);

        assert_eq!(chain_spec.bellatrix_fork_epoch, None);
    }

    #[test]
    fn test_total_terminal_difficulty() {
        assert_eq!(
            Ok(default_terminal_total_difficulty()),
            "115792089237316195423570985008687907853269984665640564039457584007913129638912"
                .parse()
        );
    }

    #[test]
    fn test_domain_builder() {
        assert_eq!(
            int_to_bytes4(ApplicationDomain::Builder.get_domain_constant()),
            [0, 0, 0, 1]
        );
    }

    #[test]
    fn test_max_network_limits_overflow() {
        let mut spec = MainnetEthSpec::default_spec();
        // Should not overflow
        let _ = spec.max_message_size();
        let _ = spec.max_compressed_len();

        spec.max_payload_size *= 10;
        // Should not overflow even with a 10x increase in max
        let _ = spec.max_message_size();
        let _ = spec.max_compressed_len();
    }

    #[test]
    fn min_epochs_for_data_sidecar_requests_deneb() {
        type E = MainnetEthSpec;
        let spec = Arc::new(ForkName::Deneb.make_genesis_spec(E::default_spec()));
        let blob_retention_epochs = spec.min_epochs_for_blob_sidecars_requests;

        // `min_epochs_for_data_sidecar_requests` cannot be earlier than Deneb fork epoch.
        assert_eq!(
            spec.deneb_fork_epoch,
            spec.min_epoch_data_availability_boundary::<E>(Epoch::new(blob_retention_epochs / 2))
        );

        let current_epoch = Epoch::new(blob_retention_epochs * 2);
        let expected_min_blob_epoch = current_epoch - blob_retention_epochs;
        assert_eq!(
            Some(expected_min_blob_epoch),
            spec.min_epoch_data_availability_boundary::<E>(current_epoch)
        );
    }

    #[test]
    fn min_epochs_for_data_sidecar_requests_fulu() {
        type E = MainnetEthSpec;
        let spec = {
            let mut spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
            // 4096 * 2 = 8192
            spec.fulu_fork_epoch = Some(Epoch::new(spec.min_epochs_for_blob_sidecars_requests * 2));
            // set a different value for testing purpose, 4096 / 2 = 2048
            spec.min_epochs_for_data_column_sidecars_requests =
                spec.min_epochs_for_blob_sidecars_requests / 2;
            Arc::new(spec)
        };
        let blob_retention_epochs = spec.min_epochs_for_blob_sidecars_requests;
        let data_column_retention_epochs = spec.min_epochs_for_data_column_sidecars_requests;

        // `min_epochs_for_data_sidecar_requests` at fulu fork epoch still uses `min_epochs_for_blob_sidecars_requests`
        let fulu_fork_epoch = spec.fulu_fork_epoch.unwrap();
        let expected_blob_retention_epoch = fulu_fork_epoch - blob_retention_epochs;
        assert_eq!(
            Some(expected_blob_retention_epoch),
            spec.min_epoch_data_availability_boundary::<E>(fulu_fork_epoch)
        );

        // Now, the blob retention period starts still before the fulu fork epoch, so the boundary
        // should respect the blob retention period.
        let half_blob_retention_epoch_after_fulu = fulu_fork_epoch + (blob_retention_epochs / 2);
        let expected_blob_retention_epoch =
            half_blob_retention_epoch_after_fulu - blob_retention_epochs;
        assert_eq!(
            Some(expected_blob_retention_epoch),
            spec.min_epoch_data_availability_boundary::<E>(half_blob_retention_epoch_after_fulu)
        );

        // If the retention period starts with the fulu fork epoch, there are no more blobs to
        // retain, and the return value will be based on the data column retention period.
        let current_epoch = fulu_fork_epoch + blob_retention_epochs;
        let expected_data_column_retention_epoch = current_epoch - data_column_retention_epochs;
        assert_eq!(
            Some(expected_data_column_retention_epoch),
            spec.min_epoch_data_availability_boundary::<E>(current_epoch)
        );
    }

    #[test]
    fn min_epochs_for_data_sidecar_requests_fulu_genesis() {
        type E = MainnetEthSpec;
        let spec = {
            // fulu active at genesis
            let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
            // set a different value for testing purpose, 4096 / 2 = 2048
            spec.min_epochs_for_data_column_sidecars_requests =
                spec.min_epochs_for_blob_sidecars_requests / 2;
            Arc::new(spec)
        };
        let blob_retention_epochs = spec.min_epochs_for_blob_sidecars_requests;
        let data_column_retention_epochs = spec.min_epochs_for_data_column_sidecars_requests;

        // If Fulu is activated at genesis, the column retention period should always be used.
        let assert_correct_boundary = |epoch| {
            let epoch = Epoch::new(epoch);
            assert_eq!(
                Some(epoch.saturating_sub(data_column_retention_epochs)),
                spec.min_epoch_data_availability_boundary::<E>(epoch)
            )
        };

        assert_correct_boundary(0);
        assert_correct_boundary(1);
        assert_correct_boundary(blob_retention_epochs - 1);
        assert_correct_boundary(blob_retention_epochs);
        assert_correct_boundary(blob_retention_epochs + 1);
        assert_correct_boundary(data_column_retention_epochs - 1);
        assert_correct_boundary(data_column_retention_epochs);
        assert_correct_boundary(data_column_retention_epochs + 1);
    }

    #[test]
    fn proposer_shuffling_decision_root_around_epoch_boundary() {
        type E = MainnetEthSpec;
        let fulu_fork_epoch = 5;
        let gloas_fork_epoch = 10;
        let spec = {
            let mut spec = ForkName::Electra.make_genesis_spec(E::default_spec());
            spec.fulu_fork_epoch = Some(Epoch::new(fulu_fork_epoch));
            spec.gloas_fork_epoch = Some(Epoch::new(gloas_fork_epoch));
            Arc::new(spec)
        };

        // For epochs prior to AND including the Fulu fork epoch, the decision slot is the end
        // of the previous epoch (i.e. only 1 slot lookahead).
        for epoch in (0..=fulu_fork_epoch).map(Epoch::new) {
            assert_eq!(
                spec.proposer_shuffling_decision_slot::<E>(epoch),
                epoch.start_slot(E::slots_per_epoch()) - 1
            );
        }

        // For epochs after Fulu, the decision slot is the end of the epoch two epochs prior.
        for epoch in ((fulu_fork_epoch + 1)..=(gloas_fork_epoch + 1)).map(Epoch::new) {
            assert_eq!(
                spec.proposer_shuffling_decision_slot::<E>(epoch),
                (epoch - 1).start_slot(E::slots_per_epoch()) - 1
            );
        }
    }

    /// Pins the deadline getters to the values `compute_derived_values` used to cache.
    #[test]
    fn deadlines_match_the_previously_cached_values() {
        fn check<E: EthSpec>(spec: ChainSpec, pre_gloas: [u64; 7], gloas: [u64; 7]) {
            let mut spec = spec.compute_derived_values::<E>();
            spec.gloas_fork_epoch = Some(Epoch::new(1));
            let deadlines = |slot: Slot| {
                [
                    spec.get_attestation_due::<E>(slot),
                    spec.get_aggregate_attestation_due::<E>(slot),
                    spec.get_sync_message_due::<E>(slot),
                    spec.get_contribution_message_due::<E>(slot),
                    spec.get_payload_due::<E>(slot),
                    spec.get_payload_attestation_due::<E>(slot),
                    spec.get_proposer_reorg_cutoff::<E>(slot),
                ]
                .map(|due| due.as_millis() as u64)
            };
            assert_eq!(deadlines(Slot::new(0)), pre_gloas);
            assert_eq!(
                deadlines(Epoch::new(1).start_slot(E::slots_per_epoch())),
                gloas
            );
        }
        check::<MainnetEthSpec>(
            ChainSpec::mainnet(),
            [3999, 8000, 3999, 8000, 6000, 9000, 2000],
            [3000, 6000, 3000, 6000, 6000, 9000, 2000],
        );
        check::<MinimalEthSpec>(
            ChainSpec::minimal(),
            [1999, 4000, 1999, 4000, 3000, 4500, 1000],
            [1500, 3000, 1500, 3000, 3000, 4500, 1000],
        );
        check::<crate::core::GnosisEthSpec>(
            ChainSpec::gnosis(),
            [1666, 3333, 1666, 3333, 2500, 3750, 833],
            [1250, 2500, 1250, 2500, 2500, 3750, 833],
        );
    }

    #[test]
    fn test_slot_component_duration_calculations() {
        let spec = ChainSpec::mainnet().compute_derived_values::<MainnetEthSpec>();

        // Test unaggregated attestation (3333 bps = 33.33% of 12s = 4s)
        let unagg_due = spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(unagg_due, Duration::from_millis(3999)); // 12000 * 3333 / 10000

        // Test aggregate attestation (6667 bps = 66.67% of 12s = 8s)
        let agg_due = spec.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(agg_due, Duration::from_millis(8000)); // 12000 * 6667 / 10000

        // Test sync message (3333 bps = 33.33% of 12s = 4s)
        let sync_msg_due = spec.get_sync_message_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(sync_msg_due, Duration::from_millis(3999)); // 12000 * 3333 / 10000

        // Test contribution message (6667 bps = 66.67% of 12s = 8s)
        let contribution_due = spec.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(contribution_due, Duration::from_millis(8000)); // 12000 * 6667 / 10000

        // Test slot duration
        let slot_duration = spec.genesis_slot_duration();
        assert_eq!(slot_duration, Duration::from_millis(12000));

        // Test edge cases with custom spec
        let mut custom_spec = spec.clone();

        // Edge case: 0 bps should give 0 duration
        custom_spec.attestation_due_bps = 0;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let zero_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(zero_due, Duration::from_millis(0));

        // Edge case: 10000 bps (100%) should give full slot duration
        let mut custom_spec = custom_spec;
        custom_spec.attestation_due_bps = 10_000;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let full_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(full_due, Duration::from_millis(12000));

        // Edge case: 5000 bps (50%) should give half slot duration
        let mut custom_spec = custom_spec;
        custom_spec.attestation_due_bps = 5_000;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let half_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(half_due, Duration::from_millis(6000));

        // Test with different slot duration (Gnosis: 5s slots)
        let mut custom_spec = custom_spec;
        custom_spec.slot_duration_ms = 5000;
        custom_spec.attestation_due_bps = 3333;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let gnosis_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(gnosis_due, Duration::from_millis(1666)); // 5000 * 3333 / 10000

        // Test with very small slot duration
        let mut custom_spec = custom_spec;
        custom_spec.slot_duration_ms = 1000; // 1 second
        custom_spec.attestation_due_bps = 3333;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let small_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(small_due, Duration::from_millis(333)); // 1000 * 3333 / 10000

        // Test rounding behavior with non-divisible values
        let mut custom_spec = custom_spec;
        custom_spec.slot_duration_ms = 12000;
        custom_spec.attestation_due_bps = 1; // 0.01%
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        let tiny_due = custom_spec.get_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(tiny_due, Duration::from_millis(1)); // 12000 * 1 / 10000 = 1.2 -> 1

        // Test payload due (5000 bps = 50% of 12s = 6s)
        let spec = ChainSpec::mainnet().compute_derived_values::<MainnetEthSpec>();
        let payload_due = spec.get_payload_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(payload_due, Duration::from_millis(6000)); // 12000 * 5000 / 10000

        // Test payload attestation due (7500 bps = 75% of 12s = 9s)
        let payload_att_due = spec.get_payload_attestation_due::<MainnetEthSpec>(Slot::new(0));
        assert_eq!(payload_att_due, Duration::from_millis(9000)); // 12000 * 7500 / 10000

        // Test gloas attestation due (2500 bps = 25% of 12s = 3s)
        assert_eq!(
            ChainSpec::compute_slot_component_duration(
                spec.attestation_due_bps_gloas,
                spec.slot_duration_ms
            )
            .expect("valid slot component duration"),
            Duration::from_millis(3000)
        ); // 12000 * 2500 / 10000

        // Test gloas with custom bps
        let mut custom_spec = spec;
        custom_spec.attestation_due_bps_gloas = 5000;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        assert_eq!(
            ChainSpec::compute_slot_component_duration(
                custom_spec.attestation_due_bps_gloas,
                custom_spec.slot_duration_ms
            )
            .expect("valid slot component duration"),
            Duration::from_millis(6000)
        ); // 12000 * 5000 / 10000

        // Test Gloas aggregate attestation due with custom bps
        let mut custom_spec = custom_spec;
        custom_spec.aggregate_due_bps_gloas = 4000;
        custom_spec.gloas_fork_epoch = Some(Epoch::new(0));
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        assert_eq!(
            custom_spec.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(4800)
        ); // 12000 * 4000 / 10000

        // Test Gloas sync committee due times with custom bps
        let mut custom_spec = custom_spec;
        custom_spec.sync_message_due_bps_gloas = 4000;
        custom_spec.contribution_due_bps_gloas = 6000;
        let custom_spec = custom_spec.compute_derived_values::<MainnetEthSpec>();
        assert_eq!(
            custom_spec.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(4800)
        ); // 12000 * 4000 / 10000
        assert_eq!(
            custom_spec.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(7200)
        ); // 12000 * 6000 / 10000
    }

    #[test]
    fn test_attestation_due_is_fork_aware() {
        type E = MainnetEthSpec;

        let gloas_fork_epoch = Epoch::new(1);
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);
        let spec = spec.compute_derived_values::<E>();
        let first_gloas_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());

        assert_eq!(
            spec.get_attestation_due::<E>(first_gloas_slot - 1),
            Duration::from_millis(3999)
        );
        assert_eq!(
            spec.get_attestation_due::<E>(first_gloas_slot),
            Duration::from_millis(3000)
        );
        assert_eq!(
            spec.get_attestation_due::<E>(first_gloas_slot + 1),
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn test_aggregate_attestation_due_is_fork_aware() {
        type E = MainnetEthSpec;

        let gloas_fork_epoch = Epoch::new(1);
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);
        let spec = spec.compute_derived_values::<E>();
        let first_gloas_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());

        assert_eq!(
            spec.get_aggregate_attestation_due::<E>(first_gloas_slot - 1),
            Duration::from_millis(8000)
        );
        assert_eq!(
            spec.get_aggregate_attestation_due::<E>(first_gloas_slot),
            Duration::from_millis(6000)
        );
        assert_eq!(
            spec.get_aggregate_attestation_due::<E>(first_gloas_slot + 1),
            Duration::from_millis(6000)
        );
    }

    #[test]
    fn test_sync_message_due_is_fork_aware() {
        type E = MainnetEthSpec;

        let gloas_fork_epoch = Epoch::new(1);
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);
        let spec = spec.compute_derived_values::<E>();
        let first_gloas_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());

        assert_eq!(
            spec.get_sync_message_due::<E>(first_gloas_slot - 1),
            Duration::from_millis(3999)
        );
        assert_eq!(
            spec.get_sync_message_due::<E>(first_gloas_slot),
            Duration::from_millis(3000)
        );
        assert_eq!(
            spec.get_sync_message_due::<E>(first_gloas_slot + 1),
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn slot_duration_changes_at_the_heze_fork_epoch() {
        let mut spec = ChainSpec::mainnet();
        spec.slot_duration_ms_heze = 10000;
        assert_eq!(
            spec.slot_duration_schedule(),
            slot_duration_schedule(&[(0, 12000)])
        );
        spec.heze_fork_epoch = Some(spec.far_future_epoch);
        assert_eq!(
            spec.slot_duration_schedule(),
            slot_duration_schedule(&[(0, 12000)])
        );

        spec.heze_fork_epoch = Some(Epoch::new(10));
        assert_eq!(
            spec.get_slot_durations().collect::<Vec<_>>(),
            vec![(Epoch::new(0), 12000), (Epoch::new(10), 10000)]
        );
        assert_eq!(
            spec.slot_duration_schedule(),
            slot_duration_schedule(&[(0, 12000), (10, 10000)])
        );
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(9)), 12000);
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(10)), 10000);
    }

    #[test]
    fn heze_at_genesis_uses_the_eip8198_slot_duration_from_genesis() {
        let mut spec = ChainSpec::mainnet();
        spec.slot_duration_ms_heze = 10000;
        spec.heze_fork_epoch = Some(Epoch::new(0));
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(0)), 10000);
        let schedule = spec.slot_duration_schedule();
        assert_eq!(schedule, slot_duration_schedule(&[(0, 10000)]));
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        assert_eq!(
            schedule.compute_time_at_slot_ms(slots_per_epoch, 0, Slot::new(3)),
            Ok(30000)
        );
        assert_eq!(
            schedule.compute_slot_at_time_ms(slots_per_epoch, 0, 30000),
            Ok(Slot::new(3))
        );
    }

    #[test]
    fn slot_duration_ms_heze_config() {
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&ChainSpec::mainnet());
        config.heze_fork_epoch = Some(MaybeQuoted {
            value: Epoch::new(10),
        });
        assert_eq!(config.slot_duration_ms_heze.map(|q| q.value), Some(12000));
        config.slot_duration_ms_heze = Some(MaybeQuoted { value: 10000 });
        let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).expect("valid config");
        assert_eq!(spec.slot_duration_ms_heze, 10000);
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(10)), 10000);

        config.slot_duration_ms_heze = None;
        let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).expect("valid config");
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(10)), 12000);

        for invalid in [0, 10500, u64::MAX / 1000 * 1000] {
            config.slot_duration_ms_heze = Some(MaybeQuoted { value: invalid });
            assert!(ChainSpec::from_config::<MainnetEthSpec>(&config).is_none());
        }

        // Without the key, a slot duration that is not a whole second still loads.
        config.slot_duration_ms_heze = None;
        config.seconds_per_slot = None;
        config.slot_duration_ms = Some(MaybeQuoted { value: 1500 });
        let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).expect("valid config");
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(10)), 1500);
    }

    #[test]
    fn deadlines_use_the_slot_duration_at_the_heze_fork() {
        let mut spec = ChainSpec::mainnet();
        spec.slot_duration_ms_heze = 10000;
        spec.heze_fork_epoch = Some(Epoch::new(10));
        let spec = spec.compute_derived_values::<MainnetEthSpec>();
        let pre_fork_slot = Slot::new(319);
        let fork_slot = Slot::new(320);
        let later_slot = Slot::new(700);
        let at_fork = |bps: u64| Duration::from_millis(bps * 10000 / BASIS_POINTS);
        let at_genesis = |bps: u64| Duration::from_millis(bps * 12000 / BASIS_POINTS);

        assert_eq!(
            spec.get_attestation_due::<MainnetEthSpec>(pre_fork_slot),
            at_genesis(spec.attestation_due_bps)
        );
        assert_eq!(
            spec.get_proposer_reorg_cutoff::<MainnetEthSpec>(pre_fork_slot),
            at_genesis(spec.proposer_reorg_cutoff_bps)
        );
        for slot in [fork_slot, later_slot] {
            assert_eq!(
                spec.get_attestation_due::<MainnetEthSpec>(slot),
                at_fork(spec.attestation_due_bps_gloas)
            );
            assert_eq!(
                spec.get_aggregate_attestation_due::<MainnetEthSpec>(slot),
                at_fork(spec.aggregate_due_bps_gloas)
            );
            assert_eq!(
                spec.get_sync_message_due::<MainnetEthSpec>(slot),
                at_fork(spec.sync_message_due_bps_gloas)
            );
            assert_eq!(
                spec.get_contribution_message_due::<MainnetEthSpec>(slot),
                at_fork(spec.contribution_due_bps_gloas)
            );
            assert_eq!(
                spec.get_payload_due::<MainnetEthSpec>(slot),
                at_fork(spec.payload_due_bps)
            );
            assert_eq!(
                spec.get_payload_attestation_due::<MainnetEthSpec>(slot),
                at_fork(spec.payload_attestation_due_bps)
            );
            assert_eq!(
                spec.get_proposer_reorg_cutoff::<MainnetEthSpec>(slot),
                at_fork(spec.proposer_reorg_cutoff_bps)
            );
        }
    }

    #[test]
    fn test_contribution_message_due_is_fork_aware() {
        type E = MainnetEthSpec;

        let gloas_fork_epoch = Epoch::new(1);
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);
        let spec = spec.compute_derived_values::<E>();
        let first_gloas_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());

        assert_eq!(
            spec.get_contribution_message_due::<E>(first_gloas_slot - 1),
            Duration::from_millis(8000)
        );
        assert_eq!(
            spec.get_contribution_message_due::<E>(first_gloas_slot),
            Duration::from_millis(6000)
        );
        assert_eq!(
            spec.get_contribution_message_due::<E>(first_gloas_slot + 1),
            Duration::from_millis(6000)
        );
    }

    #[test]
    fn test_default_duration_values_without_compute_derived_values() {
        // Verify that mainnet, minimal, and gnosis have correct pre-computed defaults
        // without needing to call compute_derived_values()
        let mainnet = ChainSpec::mainnet();
        assert_eq!(
            mainnet.get_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3999)
        );
        assert_eq!(
            mainnet.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(8000)
        );
        assert_eq!(
            mainnet.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3999)
        );
        assert_eq!(
            mainnet.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(8000)
        );

        // Mainnet payload due: 12000ms slots, 5000 bps = 6000ms
        assert_eq!(
            mainnet.get_payload_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(6000)
        );
        assert_eq!(
            mainnet.get_payload_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(9000)
        );

        // Mainnet gloas: 12000ms slots, 2500 bps = 3000ms
        assert_eq!(
            ChainSpec::compute_slot_component_duration(
                mainnet.attestation_due_bps_gloas,
                mainnet.slot_duration_ms
            )
            .expect("valid slot component duration"),
            Duration::from_millis(3000)
        );
        let mut mainnet_gloas = mainnet.clone();
        mainnet_gloas.gloas_fork_epoch = Some(Epoch::new(0));
        assert_eq!(
            mainnet_gloas.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(6000)
        );
        assert_eq!(
            mainnet_gloas.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3000)
        );
        assert_eq!(
            mainnet_gloas.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(6000)
        );

        // Minimal spec: 6000ms slots, 3333 bps = 1999ms, 6667 bps = 4000ms
        let minimal = ChainSpec::minimal();
        assert_eq!(
            minimal.get_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1999)
        );
        assert_eq!(
            minimal.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(4000)
        );
        assert_eq!(
            minimal.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1999)
        );
        assert_eq!(
            minimal.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(4000)
        );
        // Minimal payload due: 6000ms slots, 5000 bps = 3000ms
        assert_eq!(
            minimal.get_payload_due::<MinimalEthSpec>(Slot::new(0)),
            Duration::from_millis(3000)
        );
        assert_eq!(
            minimal.get_payload_attestation_due::<MinimalEthSpec>(Slot::new(0)),
            Duration::from_millis(4500)
        );

        // Minimal gloas: 6000ms slots, 2500 bps = 1500ms
        assert_eq!(
            ChainSpec::compute_slot_component_duration(
                minimal.attestation_due_bps_gloas,
                minimal.slot_duration_ms
            )
            .expect("valid slot component duration"),
            Duration::from_millis(1500)
        );
        let mut minimal_gloas = minimal.clone();
        minimal_gloas.gloas_fork_epoch = Some(Epoch::new(0));
        assert_eq!(
            minimal_gloas.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3000)
        );
        assert_eq!(
            minimal_gloas.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1500)
        );
        assert_eq!(
            minimal_gloas.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3000)
        );

        // Gnosis spec: 5000ms slots, 3333 bps = 1666ms, 6667 bps = 3333ms
        let gnosis = ChainSpec::gnosis();
        assert_eq!(
            gnosis.get_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1666)
        );
        assert_eq!(
            gnosis.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3333)
        );
        assert_eq!(
            gnosis.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1666)
        );
        assert_eq!(
            gnosis.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3333)
        );
        // Gnosis payload due: 5000ms slots, 5000 bps = 2500ms
        assert_eq!(
            gnosis.get_payload_due::<crate::core::GnosisEthSpec>(Slot::new(0)),
            Duration::from_millis(2500)
        );
        assert_eq!(
            gnosis.get_payload_attestation_due::<crate::core::GnosisEthSpec>(Slot::new(0)),
            Duration::from_millis(3750)
        );

        // Gnosis gloas: 5000ms slots, 2500 bps = 1250ms
        assert_eq!(
            ChainSpec::compute_slot_component_duration(
                gnosis.attestation_due_bps_gloas,
                gnosis.slot_duration_ms
            )
            .expect("valid slot component duration"),
            Duration::from_millis(1250)
        );
        let mut gnosis_gloas = gnosis.clone();
        gnosis_gloas.gloas_fork_epoch = Some(Epoch::new(0));
        assert_eq!(
            gnosis_gloas.get_aggregate_attestation_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(2500)
        );
        assert_eq!(
            gnosis_gloas.get_sync_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(1250)
        );
        assert_eq!(
            gnosis_gloas.get_contribution_message_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(2500)
        );
    }

    #[test]
    #[should_panic(expected = "exceeds slot duration")]
    fn test_compute_derived_values_panics_on_invalid_bps_values() {
        let mut spec = ChainSpec::mainnet();
        // 15000 bps = 150% of slot duration, which is invalid
        spec.attestation_due_bps = 15000;
        spec.compute_derived_values::<MainnetEthSpec>();
    }

    fn slot_duration_schedule(entries: &[(u64, u64)]) -> SlotDurationSchedule {
        SlotDurationSchedule::new(
            entries
                .iter()
                .map(|&(epoch, slot_duration_ms)| SlotDurationScheduleEntry {
                    epoch: Epoch::new(epoch),
                    slot_duration_ms,
                })
                .collect(),
        )
    }

    #[test]
    fn later_slot_duration_wins_on_duplicate_epoch() {
        let slot_durations = [
            (Epoch::new(0), 12000),
            (Epoch::new(0), 6000),
            (Epoch::new(2), 4000),
            (Epoch::new(2), 2000),
        ];
        let schedule = ChainSpec::slot_duration_schedule_from(slot_durations.into_iter());
        assert_eq!(schedule, slot_duration_schedule(&[(0, 6000), (2, 2000)]));
        assert_eq!(
            schedule.slot_duration_ms_for_epoch(Epoch::new(0)),
            Some(6000)
        );
        assert_eq!(
            schedule.slot_duration_ms_for_epoch(Epoch::new(2)),
            Some(2000)
        );

        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let fork_slot = Epoch::new(2).start_slot(slots_per_epoch);
        let fork_time_ms = fork_slot.as_u64() * 6000;
        assert_eq!(
            schedule.compute_time_at_slot_ms(slots_per_epoch, 0, fork_slot + 1),
            Ok(fork_time_ms + 2000)
        );
        assert_eq!(
            schedule.compute_slot_at_time_ms(slots_per_epoch, 0, fork_time_ms + 2000),
            Ok(fork_slot + 1)
        );

        let mut spec = ChainSpec::mainnet();
        spec.slot_component_durations =
            spec.compute_slot_component_durations(slot_durations.into_iter());
        assert_eq!(
            spec.get_payload_due::<MainnetEthSpec>(Slot::new(0)),
            Duration::from_millis(3000)
        );
        assert_eq!(
            spec.get_payload_due::<MainnetEthSpec>(fork_slot),
            Duration::from_millis(1000)
        );
    }

    #[test]
    fn slot_durations_start_at_genesis() {
        let spec = ChainSpec::mainnet();
        assert_eq!(
            spec.get_slot_durations().collect::<Vec<_>>(),
            vec![(Epoch::new(0), 12000)]
        );
        assert_eq!(
            spec.slot_duration_schedule(),
            slot_duration_schedule(&[(0, 12000)])
        );
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(0)), 12000);
        assert_eq!(spec.get_slot_duration_ms(Epoch::new(1_000_000)), 12000);
    }

    #[test]
    fn compute_time_at_slot_in_seconds() {
        type E = MainnetEthSpec;
        let spec = ChainSpec::mainnet();
        assert_eq!(spec.compute_time_at_slot::<E>(100, Slot::new(3)), Ok(136));
        assert_eq!(spec.compute_slot_at_time::<E>(100, 136), Ok(Slot::new(3)));
        assert_eq!(spec.compute_slot_at_time::<E>(100, 147), Ok(Slot::new(3)));
        assert!(spec.compute_slot_at_time::<E>(100, 99).is_err());
    }

    #[test]
    fn min_blob_data_retention_ms_matches_data_column_retention_epochs() {
        for (spec, slots_per_epoch) in [
            (ChainSpec::mainnet(), MainnetEthSpec::slots_per_epoch()),
            (ChainSpec::minimal(), MinimalEthSpec::slots_per_epoch()),
            (
                ChainSpec::gnosis(),
                crate::core::GnosisEthSpec::slots_per_epoch(),
            ),
        ] {
            assert_eq!(
                spec.min_blob_data_retention_ms,
                spec.min_epochs_for_data_column_sidecars_requests
                    * slots_per_epoch
                    * spec.slot_duration_ms
            );
        }
    }

    #[test]
    fn min_blob_data_retention_ms_defaults_to_the_data_column_retention_window() {
        let mainnet = ChainSpec::mainnet();
        let mut config = Config::from_chain_spec::<MainnetEthSpec>(&mainnet);
        config.min_blob_data_retention_ms = None;
        config.min_epochs_for_data_column_sidecars_requests = 100;
        let spec = config
            .apply_to_chain_spec::<MainnetEthSpec>(&mainnet)
            .unwrap();
        assert_eq!(spec.min_blob_data_retention_ms, 100 * 32 * 12000);
    }

    #[test]
    fn data_retention_window_keeps_its_length_in_ms_after_eip8198() {
        type E = MainnetEthSpec;
        let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        spec.heze_fork_epoch = Some(Epoch::new(10000));
        spec.slot_duration_ms_heze = 6000;

        assert_eq!(
            spec.min_epoch_data_availability_boundary::<E>(Epoch::new(9999)),
            Some(Epoch::new(5903))
        );
        assert_eq!(
            spec.min_epoch_data_availability_boundary::<E>(Epoch::new(10000)),
            Some(Epoch::new(5904))
        );
        assert_eq!(
            spec.min_epoch_data_availability_boundary::<E>(Epoch::new(14096)),
            Some(Epoch::new(7952))
        );
        assert_eq!(
            spec.compute_blob_data_retention_start_epoch::<E>(Epoch::new(100)),
            Ok(Epoch::new(0))
        );

        spec.fulu_fork_epoch = Some(Epoch::new(6000));
        assert_eq!(
            spec.compute_blob_data_retention_start_epoch::<E>(Epoch::new(10096)),
            Ok(Epoch::new(5952))
        );
        assert_eq!(
            spec.min_epoch_data_availability_boundary::<E>(Epoch::new(10096)),
            Some(Epoch::new(6000))
        );
    }

    #[test]
    fn gossip_seen_ttl_follows_the_slot_duration() {
        type E = MainnetEthSpec;
        let mut spec = ChainSpec::mainnet();
        let seen_ttl = |spec: &ChainSpec, epoch: u64| spec.gossip_seen_ttl::<E>(Epoch::new(epoch));
        assert_eq!(seen_ttl(&spec, 0), Duration::from_secs(2 * 32 * 12));

        spec.slot_duration_ms_heze = 10000;
        spec.heze_fork_epoch = Some(Epoch::new(10));
        assert_eq!(seen_ttl(&spec, 8), Duration::from_secs(2 * 32 * 12));
        assert_eq!(seen_ttl(&spec, 9), Duration::from_secs(32 * 12 + 32 * 10));
        assert_eq!(seen_ttl(&spec, 10), Duration::from_secs(2 * 32 * 10));
    }

    #[test]
    fn slot_time_mapping_matches_linear_mapping_without_schedule() {
        let spec = ChainSpec::mainnet();
        let genesis_time_ms = 1_606_824_023_000;
        for slot in [0, 1, 31, 32, 12_345, 10_000_000] {
            assert_eq!(
                spec.slot_duration_schedule().compute_time_at_slot_ms(
                    MainnetEthSpec::slots_per_epoch(),
                    genesis_time_ms,
                    Slot::new(slot)
                ),
                Ok(genesis_time_ms + slot * 12000)
            );
        }
        for offset_ms in [0, 1, 11_999, 12_000, 123_456_789] {
            assert_eq!(
                spec.slot_duration_schedule().compute_slot_at_time_ms(
                    MainnetEthSpec::slots_per_epoch(),
                    genesis_time_ms,
                    genesis_time_ms + offset_ms
                ),
                Ok(Slot::new(offset_ms / 12000))
            );
        }
        assert!(
            spec.slot_duration_schedule()
                .compute_slot_at_time_ms(
                    MainnetEthSpec::slots_per_epoch(),
                    genesis_time_ms,
                    genesis_time_ms - 1
                )
                .is_err()
        );
    }

    #[test]
    fn slot_time_mapping_ignores_unreachable_entries() {
        let schedule = slot_duration_schedule(&[(0, 12000), (u64::MAX, 6000)]);
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        assert_eq!(
            schedule.compute_slot_at_time_ms(slots_per_epoch, 0, 120_000),
            Ok(Slot::new(10))
        );
        assert_eq!(
            schedule.compute_time_at_slot_ms(slots_per_epoch, 0, Slot::new(10)),
            Ok(120_000)
        );
    }

    #[test]
    fn slot_time_mapping_across_slot_duration_changes() {
        let schedule = slot_duration_schedule(&[(0, 12000), (10, 10000), (20, 6000)]);
        let genesis_time_ms = 1_000_000;
        let time_at = |slot: u64| {
            schedule
                .compute_time_at_slot_ms(
                    MainnetEthSpec::slots_per_epoch(),
                    genesis_time_ms,
                    Slot::new(slot),
                )
                .unwrap()
        };
        let slot_at = |time_ms: u64| {
            schedule
                .compute_slot_at_time_ms(
                    MainnetEthSpec::slots_per_epoch(),
                    genesis_time_ms,
                    time_ms,
                )
                .unwrap()
                .as_u64()
        };
        let slot_duration_ms_at = |epoch: u64| {
            schedule
                .slot_duration_ms_for_epoch(Epoch::new(epoch))
                .unwrap()
        };

        assert_eq!(slot_duration_ms_at(9), 12000);
        assert_eq!(slot_duration_ms_at(10), 10000);
        assert_eq!(slot_duration_ms_at(19), 10000);
        assert_eq!(slot_duration_ms_at(20), 6000);

        assert_eq!(time_at(320), genesis_time_ms + 320 * 12000);
        assert_eq!(time_at(321), time_at(320) + 10000);
        assert_eq!(time_at(640), time_at(320) + 320 * 10000);
        assert_eq!(time_at(641), time_at(640) + 6000);

        for slot in 0..1024 {
            let epoch = slot / 32;
            assert_eq!(
                time_at(slot + 1) - time_at(slot),
                slot_duration_ms_at(epoch),
                "slot {slot}"
            );
            assert_eq!(slot_at(time_at(slot)), slot, "slot {slot}");
            assert_eq!(slot_at(time_at(slot + 1) - 1), slot, "slot {slot}");
        }
    }

    fn configs_base_path() -> PathBuf {
        env::var("CARGO_MANIFEST_DIR")
            .expect("should know manifest dir")
            .parse::<PathBuf>()
            .expect("should parse manifest dir as path")
            .join("configs")
    }

    /// Upstream config keys that Lighthouse intentionally does not include in its
    /// `Config` struct. These are forks/features not yet implemented. Update this
    /// list as new forks are added.
    const UPSTREAM_KEYS_NOT_IN_LIGHTHOUSE: &[&str] = &[
        // Forks not yet implemented
        "EIP7928_FORK_VERSION",
        "EIP7928_FORK_EPOCH",
    ];

    /// Compare a `ChainSpec` against an upstream consensus-specs config YAML file.
    ///
    /// 1. Extracts keys from the raw YAML text (to avoid yaml_serde's inability
    ///    to parse integers > u64 into `Value`/`Mapping` types) and checks that
    ///    every key is either known to `Config` or explicitly listed in
    ///    `UPSTREAM_KEYS_NOT_IN_LIGHTHOUSE`.
    /// 2. Deserializes the upstream YAML as `Config` (which has custom
    ///    deserializers for large values like `TERMINAL_TOTAL_DIFFICULTY`) and
    ///    compares against `Config::from_chain_spec`.
    fn config_test<E: EthSpec>(spec: &ChainSpec, config_name: &str) {
        let file_path = configs_base_path().join(format!("{config_name}.yaml"));
        let upstream_yaml = std::fs::read_to_string(&file_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", file_path.display()));

        // Extract top-level keys from the raw YAML text. We can't parse as
        // yaml_serde::Mapping because yaml_serde cannot represent integers
        // exceeding u64 (e.g. TERMINAL_TOTAL_DIFFICULTY). Config YAML uses a
        // simple `KEY: value` format with no indentation for top-level keys.
        let upstream_keys: BTreeSet<String> = upstream_yaml
            .lines()
            .filter_map(|line| {
                // Skip comments, blank lines, and indented lines (nested YAML).
                if line.is_empty()
                    || line.starts_with('#')
                    || line.starts_with(' ')
                    || line.starts_with('\t')
                {
                    return None;
                }
                line.split(':').next().map(|k| k.to_string())
            })
            .collect();

        // Get the set of keys that Config knows about by serializing and collecting
        // keys. Also include keys for optional fields that may be skipped during
        // serialization (e.g. CONFIG_NAME).
        let our_config = Config::from_chain_spec::<E>(spec);
        let our_yaml = yaml_serde::to_string(&our_config).expect("failed to serialize Config");
        let our_mapping: yaml_serde::Mapping =
            yaml_serde::from_str(&our_yaml).expect("failed to re-parse our Config");
        let mut known_keys: BTreeSet<String> = our_mapping
            .keys()
            .filter_map(|k| k.as_str().map(String::from))
            .collect();
        // Fields that Config knows but may skip during serialization.
        known_keys.insert("CONFIG_NAME".to_string());

        // Check for upstream keys that our Config doesn't know about.
        let mut missing_keys: Vec<&String> = upstream_keys
            .iter()
            .filter(|k| {
                !known_keys.contains(k.as_str())
                    && !UPSTREAM_KEYS_NOT_IN_LIGHTHOUSE.contains(&k.as_str())
            })
            .collect();
        missing_keys.sort();

        assert!(
            missing_keys.is_empty(),
            "Upstream {config_name} config has keys not present in Lighthouse Config \
             (add to Config or to UPSTREAM_KEYS_NOT_IN_LIGHTHOUSE): {missing_keys:?}"
        );

        // Compare values for all fields Config knows about.
        let mut upstream_config: Config = yaml_serde::from_str(&upstream_yaml)
            .unwrap_or_else(|e| panic!("failed to parse {config_name} as Config: {e}"));

        // CONFIG_NAME is network metadata (not a spec parameter), so align it
        // before comparing.
        upstream_config.config_name = our_config.config_name.clone();
        // SECONDS_PER_SLOT is deprecated upstream but we still emit it, so
        // fill it in if the upstream YAML omitted it.
        if upstream_config.seconds_per_slot.is_none() {
            upstream_config.seconds_per_slot = our_config.seconds_per_slot;
        }
        assert_eq!(
            upstream_config, our_config,
            "Config mismatch for {config_name}"
        );
    }

    #[test]
    fn mainnet_config_consistent() {
        let spec = ChainSpec::mainnet();
        config_test::<MainnetEthSpec>(&spec, "mainnet");
    }

    #[test]
    fn minimal_config_consistent() {
        let spec = ChainSpec::minimal();
        config_test::<MinimalEthSpec>(&spec, "minimal");
    }
}

#[cfg(test)]
mod slot_duration_schedule_properties {
    use super::*;
    use proptest::prelude::*;

    const SLOTS_PER_EPOCH: u64 = 32;

    fn spec_time_at_slot(schedule: &[(u64, u64)], genesis_time_ms: u128, slot: u128) -> u128 {
        let mut end_slot = slot;
        let mut time_ms = genesis_time_ms;
        for &(fork_epoch, slot_duration_ms) in schedule.iter().rev() {
            let fork_slot = u128::from(fork_epoch) * u128::from(SLOTS_PER_EPOCH);
            if fork_slot < end_slot {
                let slots = end_slot - fork_slot;
                time_ms += slots * u128::from(slot_duration_ms);
                end_slot = fork_slot;
            }
        }
        time_ms
    }

    fn spec_slot_at_time(
        schedule: &[(u64, u64)],
        genesis_time_ms: u128,
        time_ms: u128,
    ) -> Option<u128> {
        let mut start = None;
        for &(fork_epoch, fork_slot_duration_ms) in schedule {
            let fork_slot = u128::from(fork_epoch) * u128::from(SLOTS_PER_EPOCH);
            let fork_time_ms = spec_time_at_slot(schedule, genesis_time_ms, fork_slot);
            if time_ms >= fork_time_ms {
                start = Some((fork_slot, fork_time_ms, u128::from(fork_slot_duration_ms)));
            }
        }
        let (start_slot, start_time_ms, slot_duration_ms) = start?;
        let time_diff_ms = time_ms - start_time_ms;
        let slots = time_diff_ms / slot_duration_ms;
        Some(start_slot + slots)
    }

    fn to_schedule(entries: &[(u64, u64)]) -> SlotDurationSchedule {
        ChainSpec::slot_duration_schedule_from(
            entries
                .iter()
                .map(|&(epoch, slot_duration_ms)| (Epoch::new(epoch), slot_duration_ms)),
        )
    }

    fn epoch() -> impl Strategy<Value = u64> {
        prop_oneof![
            0u64..4,
            1u64..200,
            1u64..u64::MAX / SLOTS_PER_EPOCH,
            Just(u64::MAX)
        ]
    }

    fn slot_duration_ms() -> impl Strategy<Value = u64> {
        (1u64..=24).prop_map(|seconds| seconds * 1000)
    }

    fn schedule() -> impl Strategy<Value = Vec<(u64, u64)>> {
        (
            slot_duration_ms(),
            proptest::collection::vec((epoch(), slot_duration_ms()), 0..4),
        )
            .prop_map(|(genesis_slot_duration_ms, later)| {
                let mut entries = vec![(0, genesis_slot_duration_ms)];
                entries.extend(later);
                entries.sort_by_key(|&(epoch, _)| epoch);
                entries
            })
    }

    proptest! {
        #[test]
        fn time_at_slot_matches_spec(
            entries in schedule(),
            genesis_time_ms in 0u64..1 << 44,
            slot in prop_oneof![0u64..20_000, any::<u64>()],
        ) {
            let expected = spec_time_at_slot(&entries, u128::from(genesis_time_ms), u128::from(slot));
            match to_schedule(&entries).compute_time_at_slot_ms(SLOTS_PER_EPOCH, genesis_time_ms, Slot::new(slot)) {
                Ok(time_ms) => prop_assert_eq!(u128::from(time_ms), expected),
                Err(_) => prop_assert!(expected > u128::from(u64::MAX)),
            }
        }

        #[test]
        fn slot_at_time_matches_spec(
            entries in schedule(),
            genesis_time_ms in 0u64..1 << 44,
            offset_ms in prop_oneof![0u64..1 << 30, 0u64..1 << 50],
        ) {
            let time_ms = genesis_time_ms + offset_ms;
            let expected =
                spec_slot_at_time(&entries, u128::from(genesis_time_ms), u128::from(time_ms));
            let slot = to_schedule(&entries)
                .compute_slot_at_time_ms(SLOTS_PER_EPOCH, genesis_time_ms, time_ms);
            prop_assert_eq!(slot.map(|slot| u128::from(slot.as_u64())).ok(), expected);
        }

        #[test]
        fn slot_at_time_inverts_time_at_slot(
            entries in schedule(),
            genesis_time_ms in 0u64..1 << 44,
            slot in 0u64..20_000,
        ) {
            let schedule = to_schedule(&entries);
            let time_at = |slot: u64| {
                schedule
                    .compute_time_at_slot_ms(SLOTS_PER_EPOCH, genesis_time_ms, Slot::new(slot))
                    .unwrap()
            };
            let slot_at = |time_ms: u64| {
                schedule
                    .compute_slot_at_time_ms(SLOTS_PER_EPOCH, genesis_time_ms, time_ms)
                    .unwrap()
                    .as_u64()
            };
            prop_assert!(time_at(slot) < time_at(slot + 1));
            prop_assert_eq!(slot_at(time_at(slot)), slot);
            prop_assert_eq!(slot_at(time_at(slot + 1) - 1), slot);
        }

        #[test]
        fn slot_at_time_is_total_after_genesis(
            entries in schedule(),
            genesis_time_ms in 1u64..1 << 44,
            offset_ms in any::<u64>(),
        ) {
            let schedule = to_schedule(&entries);
            let time_ms = genesis_time_ms.saturating_add(offset_ms);
            prop_assert!(
                schedule
                    .compute_slot_at_time_ms(SLOTS_PER_EPOCH, genesis_time_ms, time_ms)
                    .is_ok()
            );
            prop_assert!(
                schedule
                    .compute_slot_at_time_ms(SLOTS_PER_EPOCH, genesis_time_ms, genesis_time_ms - 1)
                    .is_err()
            );
        }

        #[test]
        fn slot_duration_lookups_agree(
            heze_epoch in prop_oneof![Just(0u64), 0u64..200, Just(u64::MAX)],
            slot_duration_ms in slot_duration_ms(),
            slot_duration_ms_heze in slot_duration_ms(),
            epoch in prop_oneof![0u64..400, any::<u64>()],
        ) {
            let mut spec = ChainSpec::mainnet();
            spec.slot_duration_ms = slot_duration_ms;
            spec.slot_duration_ms_heze = slot_duration_ms_heze;
            spec.heze_fork_epoch = Some(Epoch::new(heze_epoch));
            let epoch = Epoch::new(epoch);
            prop_assert_eq!(
                spec.slot_duration_schedule().slot_duration_ms_for_epoch(epoch),
                Some(spec.get_slot_duration_ms(epoch))
            );
        }
    }
}
