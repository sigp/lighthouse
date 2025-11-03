use crate::application_domain::{APPLICATION_DOMAIN_BUILDER, ApplicationDomain};
use crate::blob_sidecar::BlobIdentifier;
use crate::data_column_sidecar::DataColumnsByRootIdentifier;
use crate::*;
use derivative::Derivative;
use ethereum_hashing::hash;
use int_to_bytes::int_to_bytes4;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_utils::quoted_u64::MaybeQuoted;
use ssz::Encode;
use std::fs::File;
use std::path::Path;
use std::time::Duration;
use tree_hash::TreeHash;

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

    /*
     * Time parameters
     */
    pub genesis_delay: u64,
    pub seconds_per_slot: u64,
    pub slot_duration_ms: u64,
    pub min_attestation_inclusion_delay: u64,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_epochs_to_inactivity_penalty: u64,
    pub min_validator_withdrawability_delay: Epoch,
    pub shard_committee_period: u64,
    pub proposer_reorg_cutoff_bps: u64,
    pub attestation_due_bps: u64,
    pub aggregate_due_bps: u64,
    pub sync_message_due_bps: u64,
    pub contribution_due_bps: u64,

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

    /*
     * Fork choice
     */
    pub proposer_score_boost: Option<u64>,
    pub reorg_head_weight_threshold: Option<u64>,
    pub reorg_parent_weight_threshold: Option<u64>,

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
    pub attestation_subnet_count: u64,
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
    pub(crate) blob_schedule: BlobSchedule,
    pub min_epochs_for_data_column_sidecars_requests: u64,

    /*
     * Networking Gloas
     */

    /*
     * Networking Derived
     *
     * When adding fields here, make sure any values are derived again during `apply_to_chain_spec`.
     */
    pub max_blocks_by_root_request: usize,
    pub max_blocks_by_root_request_deneb: usize,
    pub max_blobs_by_root_request: usize,
    pub max_data_columns_by_root_request: usize,

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
    /// `next_fork_version = current_fork_version` if no future fork is planned,
    pub fn next_fork_version<E: EthSpec>(&self, slot: Slot) -> [u8; 4] {
        match self.next_fork_epoch::<E>(slot) {
            Some((fork, _)) => self.fork_version_for_name(fork),
            None => self.fork_version_for_name(self.fork_name_at_slot::<E>(slot)),
        }
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

    /// For a given `BeaconState`, return the proportional slashing multiplier associated with its variant.
    pub fn proportional_slashing_multiplier_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> u64 {
        let fork_name = state.fork_name_unchecked();
        if fork_name >= ForkName::Bellatrix {
            self.proportional_slashing_multiplier_bellatrix
        } else if fork_name >= ForkName::Altair {
            self.proportional_slashing_multiplier_altair
        } else {
            self.proportional_slashing_multiplier
        }
    }

    /// For a given `BeaconState`, return the minimum slashing penalty quotient associated with its variant.
    pub fn min_slashing_penalty_quotient_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> u64 {
        let fork_name = state.fork_name_unchecked();
        if fork_name.electra_enabled() {
            self.min_slashing_penalty_quotient_electra
        } else if fork_name >= ForkName::Bellatrix {
            self.min_slashing_penalty_quotient_bellatrix
        } else if fork_name >= ForkName::Altair {
            self.min_slashing_penalty_quotient_altair
        } else {
            self.min_slashing_penalty_quotient
        }
    }

    /// For a given `BeaconState`, return the whistleblower reward quotient associated with its variant.
    pub fn whistleblower_reward_quotient_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> u64 {
        let fork_name = state.fork_name_unchecked();
        if fork_name.electra_enabled() {
            self.whistleblower_reward_quotient_electra
        } else {
            self.whistleblower_reward_quotient
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
    pub fn get_builder_domain(&self) -> Hash256 {
        self.compute_domain(
            Domain::ApplicationMask(ApplicationDomain::Builder),
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
    pub fn min_epoch_data_availability_boundary(&self, current_epoch: Epoch) -> Option<Epoch> {
        let fork_epoch = self.deneb_fork_epoch?;
        let blob_retention_epoch =
            current_epoch.saturating_sub(self.min_epochs_for_blob_sidecars_requests);
        match self.fulu_fork_epoch {
            Some(fulu_fork_epoch) if blob_retention_epoch > fulu_fork_epoch => Some(
                current_epoch.saturating_sub(self.min_epochs_for_data_column_sidecars_requests),
            ),
            _ => Some(std::cmp::max(fork_epoch, blob_retention_epoch)),
        }
    }

    pub fn all_data_column_sidecar_subnets(&self) -> impl Iterator<Item = DataColumnSubnetId> {
        (0..self.data_column_sidecar_subnet_count).map(DataColumnSubnetId::new)
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

            /*
             * Time parameters
             */
            genesis_delay: 604800, // 7 days
            seconds_per_slot: 12,
            slot_duration_ms: 12000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            shard_committee_period: 256,
            proposer_reorg_cutoff_bps: 1667,
            attestation_due_bps: 3333,
            aggregate_due_bps: 6667,
            sync_message_due_bps: 3333,
            contribution_due_bps: 6667,

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

            /*
             * Fork choice
             */
            proposer_score_boost: Some(40),
            reorg_head_weight_threshold: Some(20),
            reorg_parent_weight_threshold: Some(160),

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

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 1, // mainnet network id
            attestation_propagation_slot_range: default_attestation_propagation_slot_range(),
            attestation_subnet_count: 64,
            subnets_per_node: 2,
            maximum_gossip_clock_disparity: default_maximum_gossip_clock_disparity(),
            target_aggregators_per_committee: 16,
            max_payload_size: default_max_payload_size(),
            min_epochs_for_block_requests: default_min_epochs_for_block_requests(),
            ttfb_timeout: default_ttfb_timeout(),
            resp_timeout: default_resp_timeout(),
            message_domain_invalid_snappy: default_message_domain_invalid_snappy(),
            message_domain_valid_snappy: default_message_domain_valid_snappy(),
            attestation_subnet_prefix_bits: default_attestation_subnet_prefix_bits(),
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
            max_data_columns_by_root_request: default_data_columns_by_root_request(),

            /*
             * Application specific
             */
            domain_application_mask: APPLICATION_DOMAIN_BUILDER,

            /*
             * Capella params
             */
            domain_bls_to_execution_change: 10,
        }
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
            inactivity_penalty_quotient: u64::checked_pow(2, 25).expect("pow does not overflow"),
            min_slashing_penalty_quotient: 64,
            proportional_slashing_multiplier: 2,
            // Altair
            epochs_per_sync_committee_period: Epoch::new(8),
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
            gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
            gloas_fork_epoch: None,
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

            /*
             * Time parameters
             */
            genesis_delay: 6000, // 100 minutes
            seconds_per_slot: 5,
            slot_duration_ms: 5000,
            min_attestation_inclusion_delay: 1,
            min_seed_lookahead: Epoch::new(1),
            max_seed_lookahead: Epoch::new(4),
            min_epochs_to_inactivity_penalty: 4,
            min_validator_withdrawability_delay: Epoch::new(256),
            shard_committee_period: 256,
            proposer_reorg_cutoff_bps: 1667,
            attestation_due_bps: 3333,
            aggregate_due_bps: 6667,
            sync_message_due_bps: 3333,
            contribution_due_bps: 6667,

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

            /*
             * Fork choice
             */
            proposer_score_boost: Some(40),
            reorg_head_weight_threshold: Some(20),
            reorg_parent_weight_threshold: Some(160),

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
            epochs_per_sync_committee_period: Epoch::new(512),
            domain_sync_committee: 7,
            domain_sync_committee_selection_proof: 8,
            domain_contribution_and_proof: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x64],
            altair_fork_epoch: Some(Epoch::new(512)),

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
            fulu_fork_epoch: None,
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

            /*
             * Network specific
             */
            boot_nodes: vec![],
            network_id: 100, // Gnosis Chain network id
            attestation_propagation_slot_range: default_attestation_propagation_slot_range(),
            attestation_subnet_count: 64,
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
            attestation_subnet_prefix_bits: default_attestation_subnet_prefix_bits(),

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
            min_epochs_for_data_column_sidecars_requests:
                default_min_epochs_for_data_column_sidecars_requests(),
            max_data_columns_by_root_request: default_data_columns_by_root_request(),

            /*
             * Application specific
             */
            domain_application_mask: APPLICATION_DOMAIN_BUILDER,

            /*
             * Capella params
             */
            domain_bls_to_execution_change: 10,
        }
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

// A wrapper around a vector of BlobParameters to ensure that the vector is reverse
// sorted by epoch.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Derivative, Clone)]
#[derivative(PartialEq)]
pub struct BlobSchedule {
    schedule: Vec<BlobParameters>,
    // This is a hack to prevent the blob schedule being serialized on the /eth/v1/config/spec
    // endpoint prior to the Fulu fork being scheduled.
    //
    // We can remove this once Fulu is live on mainnet.
    #[derivative(PartialEq = "ignore")]
    skip_serializing: bool,
}

impl<'de> Deserialize<'de> for BlobSchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<BlobParameters>::deserialize(deserializer)?;
        Ok(BlobSchedule::new(vec))
    }
}

impl BlobSchedule {
    pub fn new(mut vec: Vec<BlobParameters>) -> Self {
        // reverse sort by epoch
        vec.sort_by(|a, b| b.epoch.cmp(&a.epoch));
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

    pub fn max_blobs_for_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.schedule
            .iter()
            .find(|entry| epoch >= entry.epoch)
            .map(|entry| entry.max_blobs_per_block)
    }

    pub fn blob_parameters_for_epoch(&self, epoch: Epoch) -> Option<BlobParameters> {
        self.schedule
            .iter()
            .find(|entry| epoch >= entry.epoch)
            .cloned()
    }

    pub const fn default() -> Self {
        // TODO(EIP-7892): think about what the default should be
        Self {
            schedule: vec![],
            skip_serializing: false,
        }
    }

    pub fn as_vec(&self) -> &Vec<BlobParameters> {
        &self.schedule
    }
}

impl Serialize for BlobSchedule {
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

impl<'a> IntoIterator for &'a BlobSchedule {
    type Item = &'a BlobParameters;
    type IntoIter = std::slice::Iter<'a, BlobParameters>;

    fn into_iter(self) -> Self::IntoIter {
        self.schedule.iter()
    }
}

impl IntoIterator for BlobSchedule {
    type Item = BlobParameters;
    type IntoIter = std::vec::IntoIter<BlobParameters>;

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

    #[serde(with = "serde_utils::quoted_u64")]
    seconds_per_slot: u64,
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
    #[serde(default = "default_attestation_subnet_prefix_bits")]
    #[serde(with = "serde_utils::quoted_u8")]
    attestation_subnet_prefix_bits: u8,
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

fn default_attestation_subnet_prefix_bits() -> u8 {
    6
}

const fn default_max_per_epoch_activation_churn_limit() -> u64 {
    8
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

fn max_blobs_by_root_request_common(max_request_blob_sidecars: u64) -> usize {
    let max_request_blob_sidecars = max_request_blob_sidecars as usize;
    let empty_blob_identifier = BlobIdentifier {
        block_root: Hash256::zero(),
        index: 0,
    };

    RuntimeVariableList::<BlobIdentifier>::new(
        vec![empty_blob_identifier; max_request_blob_sidecars],
        max_request_blob_sidecars,
    )
    .expect("creating a RuntimeVariableList of size `max_request_blob_sidecars` should succeed")
    .as_ssz_bytes()
    .len()
}

fn max_data_columns_by_root_request_common<E: EthSpec>(max_request_blocks: u64) -> usize {
    let max_request_blocks = max_request_blocks as usize;

    let empty_data_columns_by_root_id = DataColumnsByRootIdentifier {
        block_root: Hash256::zero(),
        columns: VariableList::from(vec![0; E::number_of_columns()]),
    };

    RuntimeVariableList::<DataColumnsByRootIdentifier<E>>::new(
        vec![empty_data_columns_by_root_id; max_request_blocks],
        max_request_blocks,
    )
    .expect("creating a RuntimeVariableList of size `max_request_blocks` should succeed")
    .as_ssz_bytes()
    .len()
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

            seconds_per_slot: spec.seconds_per_slot,
            seconds_per_eth1_block: spec.seconds_per_eth1_block,
            min_validator_withdrawability_delay: spec.min_validator_withdrawability_delay,
            shard_committee_period: spec.shard_committee_period,
            eth1_follow_distance: spec.eth1_follow_distance,
            subnets_per_node: spec.subnets_per_node,
            attestation_subnet_prefix_bits: spec.attestation_subnet_prefix_bits,

            inactivity_score_bias: spec.inactivity_score_bias,
            inactivity_score_recovery_rate: spec.inactivity_score_recovery_rate,
            ejection_balance: spec.ejection_balance,
            churn_limit_quotient: spec.churn_limit_quotient,
            min_per_epoch_churn_limit: spec.min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit: spec.max_per_epoch_activation_churn_limit,

            proposer_score_boost: spec.proposer_score_boost.map(|value| MaybeQuoted { value }),

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
        }
    }

    pub fn from_file(filename: &Path) -> Result<Self, String> {
        let f = File::open(filename)
            .map_err(|e| format!("Error opening spec at {}: {:?}", filename.display(), e))?;
        serde_yaml::from_reader(f)
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
            seconds_per_slot,
            seconds_per_eth1_block,
            min_validator_withdrawability_delay,
            shard_committee_period,
            eth1_follow_distance,
            subnets_per_node,
            attestation_subnet_prefix_bits,
            inactivity_score_bias,
            inactivity_score_recovery_rate,
            ejection_balance,
            min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit,
            churn_limit_quotient,
            proposer_score_boost,
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
        } = self;

        if preset_base != E::spec_name().to_string().as_str() {
            return None;
        }

        Some(ChainSpec {
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
            seconds_per_slot,
            seconds_per_eth1_block,
            min_validator_withdrawability_delay,
            shard_committee_period,
            eth1_follow_distance,
            subnets_per_node,
            inactivity_score_bias,
            inactivity_score_recovery_rate,
            ejection_balance,
            min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit,
            churn_limit_quotient,
            proposer_score_boost: proposer_score_boost.map(|q| q.value),
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
            attestation_subnet_prefix_bits,
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

            // We need to re-derive any values that might have changed in the config.
            max_blocks_by_root_request: max_blocks_by_root_request_common(max_request_blocks),
            max_blocks_by_root_request_deneb: max_blocks_by_root_request_common(
                max_request_blocks_deneb,
            ),
            max_blobs_by_root_request: max_blobs_by_root_request_common(max_request_blob_sidecars),
            max_data_columns_by_root_request: max_data_columns_by_root_request_common::<E>(
                max_request_blocks_deneb,
            ),

            number_of_custody_groups,
            data_column_sidecar_subnet_count,
            samples_per_slot,
            custody_requirement,
            blob_schedule: blob_schedule.clone(),
            validator_custody_requirement,
            balance_per_additional_custody_group,
            min_epochs_for_data_column_sidecars_requests,

            ..chain_spec.clone()
        })
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
}

#[cfg(test)]
mod yaml_tests {
    use super::*;
    use paste::paste;
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
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = File::options()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        // deserialize minimal config from file
        let from: Config = serde_yaml::from_reader(reader).expect("error while deserializing");
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
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = File::options()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: Config = serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
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
            serde_yaml::from_str(spec_contents).expect("error while deserializing");
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
        let yaml = serde_yaml::to_string(&spec.blob_schedule).expect("should serialize");

        // Deserialize back to Vec<BlobParameters> to check order
        let deserialized: Vec<BlobParameters> =
            serde_yaml::from_str(&yaml).expect("should deserialize");

        // Should be in ascending order by epoch
        assert!(
            deserialized.iter().map(|bp| bp.epoch.as_u64()).is_sorted(),
            "BlobSchedule should serialize in ascending order by epoch"
        );
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
            serde_yaml::from_str(spec_contents).expect("error while deserializing");
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
        DEPOSIT_CHAIN_ID: 1
        DEPOSIT_NETWORK_ID: 1
        DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa
        CUSTODY_REQUIREMENT: 1
        DATA_COLUMN_SIDECAR_SUBNET_COUNT: 128
        SAMPLES_PER_SLOT: 8
        "#;

        let chain_spec: Config = serde_yaml::from_str(spec).unwrap();

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
        check_default!(attestation_subnet_prefix_bits);

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
            spec.min_epoch_data_availability_boundary(Epoch::new(blob_retention_epochs / 2))
        );

        let current_epoch = Epoch::new(blob_retention_epochs * 2);
        let expected_min_blob_epoch = current_epoch - blob_retention_epochs;
        assert_eq!(
            Some(expected_min_blob_epoch),
            spec.min_epoch_data_availability_boundary(current_epoch)
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
            spec.min_epoch_data_availability_boundary(fulu_fork_epoch)
        );

        // `min_epochs_for_data_sidecar_requests` at fulu fork epoch + min_epochs_for_blob_sidecars_request
        let blob_retention_epoch_after_fulu = fulu_fork_epoch + blob_retention_epochs;
        let expected_blob_retention_epoch = blob_retention_epoch_after_fulu - blob_retention_epochs;
        assert_eq!(
            Some(expected_blob_retention_epoch),
            spec.min_epoch_data_availability_boundary(blob_retention_epoch_after_fulu)
        );

        // After the final blob retention epoch, `min_epochs_for_data_sidecar_requests` should be calculated
        // using `min_epochs_for_data_column_sidecars_request`
        let current_epoch = blob_retention_epoch_after_fulu + 1;
        let expected_data_column_retention_epoch = current_epoch - data_column_retention_epochs;
        assert_eq!(
            Some(expected_data_column_retention_epoch),
            spec.min_epoch_data_availability_boundary(current_epoch)
        );
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
}
