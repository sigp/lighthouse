use crate::{
    JustifiedBalances,
    error::Error,
    proto_array::{
        InvalidationOperation, Iter, NodeDelta, ProtoArray, ProtoNode, calculate_committee_fraction,
    },
    ssz_container::SszContainer,
};
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    time::Duration,
};
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    Slot,
};

pub const DEFAULT_PRUNE_THRESHOLD: usize = 256;

#[derive(Default, PartialEq, Clone, Encode, Decode)]
pub struct VoteTracker {
    current_root: Hash256,
    next_root: Hash256,
    current_slot: Slot,
    next_slot: Slot,
    current_payload_present: bool,
    next_payload_present: bool,
}

// Can be deleted once the V28 schema migration is buried.
// Matches the on-disk format from schema v28: current_root, next_root, next_epoch.
#[derive(Default, PartialEq, Clone, Encode, Decode)]
pub struct VoteTrackerV28 {
    current_root: Hash256,
    next_root: Hash256,
    next_epoch: Epoch,
}

// This impl is only used upon upgrade from pre-Gloas to Gloas with all pre-Gloas nodes.
// The payload status is `false` for pre-Gloas nodes.
impl From<VoteTrackerV28> for VoteTracker {
    fn from(v: VoteTrackerV28) -> Self {
        VoteTracker {
            current_root: v.current_root,
            next_root: v.next_root,
            // The v28 format stored next_epoch rather than slots. Default to 0 since the
            // vote tracker will be updated on the next attestation.
            current_slot: Slot::new(0),
            next_slot: Slot::new(0),
            current_payload_present: false,
            next_payload_present: false,
        }
    }
}

// This impl is only used upon downgrade from V29 to V28, with exclusively pre-Gloas nodes.
impl From<VoteTracker> for VoteTrackerV28 {
    fn from(v: VoteTracker) -> Self {
        // Drop the payload_present fields. This is safe because this is only called on pre-Gloas
        // nodes.
        VoteTrackerV28 {
            current_root: v.current_root,
            next_root: v.next_root,
            // The v28 format stored next_epoch. Default to 0 since the vote tracker will be
            // updated on the next attestation.
            next_epoch: Epoch::new(0),
        }
    }
}

/// Spec's `LatestMessage` type. Only used in tests.
pub struct LatestMessage {
    pub slot: Slot,
    pub root: Hash256,
    pub payload_present: bool,
}

/// Represents the verification status of an execution payload pre-Gloas.
#[derive(Clone, Copy, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[ssz(enum_behaviour = "union")]
pub enum ExecutionStatus {
    /// An EL has determined that the payload is valid.
    Valid(ExecutionBlockHash),
    /// An EL has determined that the payload is invalid.
    Invalid(ExecutionBlockHash),
    /// An EL has not yet verified the execution payload.
    Optimistic(ExecutionBlockHash),
    /// The block is either prior to the merge fork, or after the merge fork but before the terminal
    /// PoW block has been found.
    ///
    /// # Note:
    ///
    /// This `bool` only exists to satisfy our SSZ implementation which requires all variants
    /// to have a value. It can be set to anything.
    Irrelevant(bool),
}

/// Represents the status of an execution payload post-Gloas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[ssz(enum_behaviour = "tag")]
#[repr(u8)]
pub enum PayloadStatus {
    Empty = 0,
    Full = 1,
    Pending = 2,
}

/// Spec's `ForkChoiceNode` augmented with ProtoNode index.
pub struct IndexedForkChoiceNode {
    pub root: Hash256,
    pub proto_node_index: usize,
    pub payload_status: PayloadStatus,
}

impl IndexedForkChoiceNode {
    pub fn with_status(&self, payload_status: PayloadStatus) -> Self {
        Self {
            root: self.root,
            proto_node_index: self.proto_node_index,
            payload_status,
        }
    }
}

impl ExecutionStatus {
    pub fn is_execution_enabled(&self) -> bool {
        !matches!(self, ExecutionStatus::Irrelevant(_))
    }

    pub fn irrelevant() -> Self {
        ExecutionStatus::Irrelevant(false)
    }

    pub fn block_hash(&self) -> Option<ExecutionBlockHash> {
        match self {
            ExecutionStatus::Valid(hash)
            | ExecutionStatus::Invalid(hash)
            | ExecutionStatus::Optimistic(hash) => Some(*hash),
            ExecutionStatus::Irrelevant(_) => None,
        }
    }

    /// Returns `true` if the block:
    ///
    /// - Has a valid payload, OR
    /// - Does not have execution enabled.
    ///
    /// Whenever this function returns `true`, the block is *fully valid*.
    pub fn is_valid_or_irrelevant(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Valid(_) | ExecutionStatus::Irrelevant(_)
        )
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a valid payload
    ///
    /// This function will return `false` for any block from a slot prior to the Bellatrix fork.
    /// This means that some blocks that are perfectly valid will still receive a `false` response.
    /// See `Self::is_valid_or_irrelevant` for a function that will always return `true` given any
    /// perfectly valid block.
    pub fn is_valid_and_post_bellatrix(&self) -> bool {
        matches!(self, ExecutionStatus::Valid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a payload that has not yet been verified by an EL.
    pub fn is_strictly_optimistic(&self) -> bool {
        matches!(self, ExecutionStatus::Optimistic(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    ///     - Has a payload that has not yet been verified by an EL, OR.
    ///     - Has a payload that has been deemed invalid by an EL.
    pub fn is_optimistic_or_invalid(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Optimistic(_) | ExecutionStatus::Invalid(_)
        )
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has an invalid payload.
    pub fn is_invalid(&self) -> bool {
        matches!(self, ExecutionStatus::Invalid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Does not have execution enabled (before or after Bellatrix fork)
    pub fn is_irrelevant(&self) -> bool {
        matches!(self, ExecutionStatus::Irrelevant(_))
    }
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionStatus::Valid(_) => write!(f, "valid"),
            ExecutionStatus::Invalid(_) => write!(f, "invalid"),
            ExecutionStatus::Optimistic(_) => write!(f, "optimistic"),
            ExecutionStatus::Irrelevant(_) => write!(f, "irrelevant"),
        }
    }
}

/// A block that is to be applied to the fork choice.
///
/// A simplified version of `types::BeaconBlock`.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub slot: Slot,
    pub root: Hash256,
    pub parent_root: Option<Hash256>,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash.
    pub execution_status: ExecutionStatus,
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,

    /// post-Gloas fields
    pub execution_payload_parent_hash: Option<ExecutionBlockHash>,
    pub execution_payload_block_hash: Option<ExecutionBlockHash>,
    pub proposer_index: Option<u64>,
}

impl Block {
    /// Compute the proposer shuffling decision root of a child block in `child_block_epoch`.
    ///
    /// This function assumes that `child_block_epoch >= self.epoch`. It is the responsibility of
    /// the caller to check this condition, or else incorrect results will be produced.
    pub fn proposer_shuffling_root_for_child_block(
        &self,
        child_block_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Hash256 {
        let block_epoch = self.current_epoch_shuffling_id.shuffling_epoch;

        // For child blocks in the Fulu fork epoch itself, we want to use the old logic. There is no
        // lookahead in the first Fulu epoch. So we check whether Fulu is enabled at
        // `child_block_epoch - 1`, i.e. whether `child_block_epoch > fulu_fork_epoch`.
        if !spec
            .fork_name_at_epoch(child_block_epoch.saturating_sub(1_u64))
            .fulu_enabled()
        {
            // Prior to Fulu the proposer shuffling decision root for the current epoch is the same
            // as the attestation shuffling for the *next* epoch, i.e. it is determined at the start
            // of the current epoch.
            if block_epoch == child_block_epoch {
                self.next_epoch_shuffling_id.shuffling_decision_block
            } else {
                // Otherwise, the child block epoch is greater, so its decision root is its parent
                // root itself (this block's root).
                self.root
            }
        } else {
            // After Fulu the proposer shuffling is determined with lookahead, so if the block
            // lies in the same epoch as its parent, its decision root is the same as the
            // parent's current epoch attester shuffling
            //
            // i.e. the block from the end of epoch N - 2.
            if child_block_epoch == block_epoch {
                self.current_epoch_shuffling_id.shuffling_decision_block
            } else if child_block_epoch == block_epoch + 1 {
                // If the block is the next epoch, then it instead shares its decision root with
                // the parent's *next epoch* attester shuffling.
                self.next_epoch_shuffling_id.shuffling_decision_block
            } else {
                // The child block lies in the future beyond the lookahead, at the point where this
                // block (its parent) will be the decision block.
                self.root
            }
        }
    }
}

/// A Vec-wrapper which will grow to match any request.
///
/// E.g., a `get` or `insert` to an out-of-bounds element will cause the Vec to grow (using
/// Default) to the smallest size required to fulfill the request.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ElasticList<T>(pub Vec<T>);

impl<T> ElasticList<T>
where
    T: Default,
{
    fn ensure(&mut self, i: usize) {
        if self.0.len() <= i {
            self.0.resize_with(i + 1, Default::default);
        }
    }

    pub fn get_mut(&mut self, i: usize) -> &mut T {
        self.ensure(i);
        &mut self.0[i]
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

/// Information about the proposer head used for opportunistic re-orgs.
#[derive(Debug, Clone)]
pub struct ProposerHeadInfo {
    /// Information about the *current* head block, which may be re-orged.
    pub head_node: ProtoNode,
    /// Information about the parent of the current head, which should be selected as the parent
    /// for a new proposal *if* a re-org is decided on.
    pub parent_node: ProtoNode,
    /// The computed fraction of the active head committee balance below which we can re-org.
    pub re_org_head_weight_threshold: u64,
    /// The computed fraction of the active parent committee balance above which we can re-org.
    pub re_org_parent_weight_threshold: u64,
    /// The current slot from fork choice's point of view, may lead the wall-clock slot by upto
    /// 500ms.
    pub current_slot: Slot,
}

/// Error type to enable short-circuiting checks in `get_proposer_head`.
///
/// This type intentionally does not implement `Debug` so that callers are forced to handle the
/// enum.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposerHeadError<T> {
    DoNotReOrg(DoNotReOrg),
    Error(T),
}

impl<T> From<DoNotReOrg> for ProposerHeadError<T> {
    fn from(e: DoNotReOrg) -> ProposerHeadError<T> {
        Self::DoNotReOrg(e)
    }
}

impl From<Error> for ProposerHeadError<Error> {
    fn from(e: Error) -> Self {
        Self::Error(e)
    }
}

impl<T1> ProposerHeadError<T1> {
    pub fn convert_inner_error<T2>(self) -> ProposerHeadError<T2>
    where
        T2: From<T1>,
    {
        self.map_inner_error(T2::from)
    }

    pub fn map_inner_error<T2>(self, f: impl FnOnce(T1) -> T2) -> ProposerHeadError<T2> {
        match self {
            ProposerHeadError::DoNotReOrg(reason) => ProposerHeadError::DoNotReOrg(reason),
            ProposerHeadError::Error(error) => ProposerHeadError::Error(f(error)),
        }
    }
}

/// Reasons why a re-org should not be attempted.
///
/// This type intentionally does not implement `Debug` so that the `Display` impl must be used.
#[derive(Debug, Clone, PartialEq)]
pub enum DoNotReOrg {
    MissingHeadOrParentNode,
    MissingHeadFinalizedCheckpoint,
    ParentDistance,
    HeadDistance,
    ShufflingUnstable,
    DisallowedOffset {
        offset: u64,
    },
    JustificationAndFinalizationNotCompetitive,
    ChainNotFinalizing {
        epochs_since_finalization: u64,
    },
    HeadNotWeak {
        head_weight: u64,
        re_org_head_weight_threshold: u64,
    },
    ParentNotStrong {
        parent_weight: u64,
        re_org_parent_weight_threshold: u64,
    },
    HeadNotLate,
    NotProposing,
    ReOrgsDisabled,
}

impl std::fmt::Display for DoNotReOrg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::MissingHeadOrParentNode => write!(f, "unknown head or parent"),
            Self::MissingHeadFinalizedCheckpoint => write!(f, "finalized checkpoint missing"),
            Self::ParentDistance => write!(f, "parent too far from head"),
            Self::HeadDistance => write!(f, "head too far from current slot"),
            Self::ShufflingUnstable => write!(f, "shuffling unstable at epoch boundary"),
            Self::DisallowedOffset { offset } => {
                write!(f, "re-orgs disabled at offset {offset}")
            }
            Self::JustificationAndFinalizationNotCompetitive => {
                write!(f, "justification or finalization not competitive")
            }
            Self::ChainNotFinalizing {
                epochs_since_finalization,
            } => write!(
                f,
                "chain not finalizing ({epochs_since_finalization} epochs since finalization)"
            ),
            Self::HeadNotWeak {
                head_weight,
                re_org_head_weight_threshold,
            } => {
                write!(
                    f,
                    "head not weak ({head_weight}/{re_org_head_weight_threshold})"
                )
            }
            Self::ParentNotStrong {
                parent_weight,
                re_org_parent_weight_threshold,
            } => {
                write!(
                    f,
                    "parent not strong ({parent_weight}/{re_org_parent_weight_threshold})"
                )
            }
            Self::HeadNotLate => {
                write!(f, "head arrived on time")
            }
            Self::NotProposing => {
                write!(f, "not proposing at next slot")
            }
            Self::ReOrgsDisabled => {
                write!(f, "re-orgs disabled in config")
            }
        }
    }
}

/// New-type for the re-org threshold percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReOrgThreshold(pub u64);

/// New-type for disallowed re-org slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisallowedReOrgOffsets {
    // Vecs are faster than hashmaps for small numbers of items.
    offsets: Vec<u64>,
}

impl Default for DisallowedReOrgOffsets {
    fn default() -> Self {
        DisallowedReOrgOffsets { offsets: vec![0] }
    }
}

impl DisallowedReOrgOffsets {
    pub fn new<E: EthSpec>(offsets: Vec<u64>) -> Result<Self, Error> {
        for &offset in &offsets {
            if offset >= E::slots_per_epoch() {
                return Err(Error::InvalidEpochOffset(offset));
            }
        }
        Ok(Self { offsets })
    }
}

#[derive(PartialEq)]
pub struct ProtoArrayForkChoice {
    pub(crate) proto_array: ProtoArray,
    pub(crate) votes: ElasticList<VoteTracker>,
    pub(crate) balances: JustifiedBalances,
}

impl ProtoArrayForkChoice {
    #[allow(clippy::too_many_arguments)]
    pub fn new<E: EthSpec>(
        current_slot: Slot,
        finalized_block_slot: Slot,
        finalized_block_state_root: Hash256,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        current_epoch_shuffling_id: AttestationShufflingId,
        next_epoch_shuffling_id: AttestationShufflingId,
        execution_status: ExecutionStatus,
        execution_payload_parent_hash: Option<ExecutionBlockHash>,
        execution_payload_block_hash: Option<ExecutionBlockHash>,
        proposer_index: u64,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        let mut proto_array = ProtoArray {
            prune_threshold: DEFAULT_PRUNE_THRESHOLD,
            nodes: Vec::with_capacity(1),
            indices: HashMap::with_capacity(1),
        };

        let block = Block {
            slot: finalized_block_slot,
            root: finalized_checkpoint.root,
            parent_root: None,
            state_root: finalized_block_state_root,
            // We are using the finalized_root as the target_root, since it always lies on an
            // epoch boundary.
            target_root: finalized_checkpoint.root,
            current_epoch_shuffling_id,
            next_epoch_shuffling_id,
            justified_checkpoint,
            finalized_checkpoint,
            execution_status,
            unrealized_justified_checkpoint: Some(justified_checkpoint),
            unrealized_finalized_checkpoint: Some(finalized_checkpoint),
            execution_payload_parent_hash,
            execution_payload_block_hash,
            proposer_index: Some(proposer_index),
        };

        proto_array
            .on_block::<E>(
                block,
                current_slot,
                spec,
                // Anchor block is always timely (delay=0 ensures both timeliness
                // checks pass). Combined with `is_genesis` override in on_block,
                // this matches spec's `block_timeliness = {anchor: [True, True]}`.
                Duration::ZERO,
            )
            .map_err(|e| format!("Failed to add finalized block to proto_array: {:?}", e))?;

        Ok(Self {
            proto_array,
            votes: ElasticList::default(),
            balances: JustifiedBalances::default(),
        })
    }

    /// Mark a Gloas payload envelope as valid and received.
    ///
    /// This must only be called for valid Gloas payloads.
    pub fn on_valid_payload_envelope_received(
        &mut self,
        block_root: Hash256,
    ) -> Result<(), String> {
        self.proto_array
            .on_valid_payload_envelope_received(block_root)
            .map_err(|e| format!("Failed to process execution payload: {:?}", e))
    }

    /// See `ProtoArray::propagate_execution_payload_validation` for documentation.
    pub fn process_execution_payload_validation(
        &mut self,
        block_root: Hash256,
    ) -> Result<(), String> {
        self.proto_array
            .propagate_execution_payload_validation(block_root)
            .map_err(|e| format!("Failed to process valid payload: {:?}", e))
    }

    /// See `ProtoArray::propagate_execution_payload_invalidation` for documentation.
    pub fn process_execution_payload_invalidation<E: EthSpec>(
        &mut self,
        op: &InvalidationOperation,
        finalized_checkpoint: Checkpoint,
    ) -> Result<(), String> {
        self.proto_array
            .propagate_execution_payload_invalidation::<E>(op, finalized_checkpoint)
            .map_err(|e| format!("Failed to process invalid payload: {:?}", e))
    }

    pub fn process_attestation(
        &mut self,
        validator_index: usize,
        block_root: Hash256,
        attestation_slot: Slot,
        payload_present: bool,
    ) -> Result<(), String> {
        let vote = self.votes.get_mut(validator_index);

        if attestation_slot > vote.next_slot || *vote == VoteTracker::default() {
            vote.next_root = block_root;
            vote.next_slot = attestation_slot;
            vote.next_payload_present = payload_present;
        }

        Ok(())
    }

    /// Process a PTC vote by setting the appropriate bits on the target block's V29 node.
    ///
    /// `ptc_index` is the voter's position in the PTC committee (resolved by the caller).
    /// This writes directly to the node's bitfields, bypassing the delta pipeline.
    pub fn process_payload_attestation(
        &mut self,
        block_root: Hash256,
        ptc_index: usize,
        payload_present: bool,
        blob_data_available: bool,
    ) -> Result<(), String> {
        let node_index = self
            .proto_array
            .indices
            .get(&block_root)
            .copied()
            .ok_or_else(|| {
                format!("process_payload_attestation: unknown block root {block_root:?}")
            })?;
        let node = self.proto_array.nodes.get_mut(node_index).ok_or_else(|| {
            format!("process_payload_attestation: invalid node index {node_index}")
        })?;
        let v29 = node
            .as_v29_mut()
            .map_err(|_| format!("process_payload_attestation: node {block_root:?} is not V29"))?;

        v29.payload_timeliness_votes
            .set(ptc_index, payload_present)
            .map_err(|e| format!("process_payload_attestation: timeliness set failed: {e:?}"))?;
        v29.payload_data_availability_votes
            .set(ptc_index, blob_data_available)
            .map_err(|e| {
                format!("process_payload_attestation: data availability set failed: {e:?}")
            })?;

        Ok(())
    }

    pub fn process_block<E: EthSpec>(
        &mut self,
        block: Block,
        current_slot: Slot,
        spec: &ChainSpec,
        time_into_slot: Duration,
    ) -> Result<(), String> {
        if block.parent_root.is_none() {
            return Err("Missing parent root".to_string());
        }

        self.proto_array
            .on_block::<E>(block, current_slot, spec, time_into_slot)
            .map_err(|e| format!("process_block_error: {:?}", e))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn find_head<E: EthSpec>(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: &JustifiedBalances,
        proposer_boost_root: Hash256,
        equivocating_indices: &BTreeSet<u64>,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<(Hash256, PayloadStatus), String> {
        let old_balances = &mut self.balances;
        let new_balances = justified_state_balances;
        let node_slots = self
            .proto_array
            .nodes
            .iter()
            .map(|node| node.slot())
            .collect::<Vec<_>>();

        let deltas = compute_deltas(
            &self.proto_array.indices,
            &node_slots,
            &mut self.votes,
            &old_balances.effective_balances,
            &new_balances.effective_balances,
            equivocating_indices,
        )
        .map_err(|e| format!("find_head compute_deltas failed: {:?}", e))?;

        self.proto_array
            .apply_score_changes::<E>(deltas)
            .map_err(|e| format!("find_head apply_score_changes failed: {:?}", e))?;

        *old_balances = new_balances.clone();

        self.proto_array
            .find_head::<E>(
                &justified_checkpoint.root,
                current_slot,
                justified_checkpoint,
                finalized_checkpoint,
                proposer_boost_root,
                new_balances,
                spec,
            )
            .map_err(|e| format!("find_head failed: {:?}", e))
    }

    /// Get the block to propose on during `current_slot`.
    ///
    /// This function returns a *definitive* result which should be acted on.
    #[allow(clippy::too_many_arguments)]
    pub fn get_proposer_head<E: EthSpec>(
        &self,
        current_slot: Slot,
        canonical_head: Hash256,
        justified_balances: &JustifiedBalances,
        re_org_head_threshold: ReOrgThreshold,
        re_org_parent_threshold: ReOrgThreshold,
        disallowed_offsets: &DisallowedReOrgOffsets,
        max_epochs_since_finalization: Epoch,
    ) -> Result<ProposerHeadInfo, ProposerHeadError<Error>> {
        let info = self.get_proposer_head_info::<E>(
            current_slot,
            canonical_head,
            justified_balances,
            re_org_head_threshold,
            re_org_parent_threshold,
            disallowed_offsets,
            max_epochs_since_finalization,
        )?;

        // Only re-org a single slot. This prevents cascading failures during asynchrony.
        let head_slot_ok = info.head_node.slot().saturating_add(1_u64) == current_slot;
        if !head_slot_ok {
            return Err(DoNotReOrg::HeadDistance.into());
        }

        // Only re-org if the head's weight is less than the heads configured committee fraction.
        let head_weight = info.head_node.weight();
        let re_org_head_weight_threshold = info.re_org_head_weight_threshold;
        let weak_head = head_weight < re_org_head_weight_threshold;
        if !weak_head {
            return Err(DoNotReOrg::HeadNotWeak {
                head_weight,
                re_org_head_weight_threshold,
            }
            .into());
        }

        // Spec: `is_parent_strong`. Use payload-aware weight matching the
        // payload path the head node is on from its parent.
        let parent_payload_status = info.head_node.get_parent_payload_status();
        let parent_weight = info.parent_node.attestation_score(parent_payload_status);
        let re_org_parent_weight_threshold = info.re_org_parent_weight_threshold;
        let parent_strong = parent_weight > re_org_parent_weight_threshold;
        if !parent_strong {
            return Err(DoNotReOrg::ParentNotStrong {
                parent_weight,
                re_org_parent_weight_threshold,
            }
            .into());
        }

        // All checks have passed, build upon the parent to re-org the head.
        Ok(info)
    }

    /// Get information about the block to propose on during `current_slot`.
    ///
    /// This function returns a *partial* result which must be processed further.
    #[allow(clippy::too_many_arguments)]
    pub fn get_proposer_head_info<E: EthSpec>(
        &self,
        current_slot: Slot,
        canonical_head: Hash256,
        justified_balances: &JustifiedBalances,
        re_org_head_threshold: ReOrgThreshold,
        re_org_parent_threshold: ReOrgThreshold,
        disallowed_offsets: &DisallowedReOrgOffsets,
        max_epochs_since_finalization: Epoch,
    ) -> Result<ProposerHeadInfo, ProposerHeadError<Error>> {
        let mut nodes = self
            .proto_array
            .iter_nodes(&canonical_head)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();

        let parent_node = nodes.pop().ok_or(DoNotReOrg::MissingHeadOrParentNode)?;
        let head_node = nodes.pop().ok_or(DoNotReOrg::MissingHeadOrParentNode)?;

        let parent_slot = parent_node.slot();
        let head_slot = head_node.slot();
        let re_org_block_slot = head_slot.saturating_add(1_u64);

        // Check finalization distance.
        let proposal_epoch = re_org_block_slot.epoch(E::slots_per_epoch());
        let finalized_epoch = head_node
            .unrealized_finalized_checkpoint()
            .ok_or(DoNotReOrg::MissingHeadFinalizedCheckpoint)?
            .epoch;
        let epochs_since_finalization = proposal_epoch.saturating_sub(finalized_epoch).as_u64();
        if epochs_since_finalization > max_epochs_since_finalization.as_u64() {
            return Err(DoNotReOrg::ChainNotFinalizing {
                epochs_since_finalization,
            }
            .into());
        }

        // Check parent distance from head.
        // Do not check head distance from current slot, as that condition needs to be
        // late-evaluated and is elided when `current_slot == head_slot`.
        let parent_slot_ok = parent_slot + 1 == head_slot;
        if !parent_slot_ok {
            return Err(DoNotReOrg::ParentDistance.into());
        }

        // Check shuffling stability.
        let shuffling_stable = re_org_block_slot % E::slots_per_epoch() != 0;
        if !shuffling_stable {
            return Err(DoNotReOrg::ShufflingUnstable.into());
        }

        // Check allowed slot offsets.
        let offset = (re_org_block_slot % E::slots_per_epoch()).as_u64();
        if disallowed_offsets.offsets.contains(&offset) {
            return Err(DoNotReOrg::DisallowedOffset { offset }.into());
        }

        // Check FFG.
        let ffg_competitive = parent_node.unrealized_justified_checkpoint()
            == head_node.unrealized_justified_checkpoint()
            && parent_node.unrealized_finalized_checkpoint()
                == head_node.unrealized_finalized_checkpoint();
        if !ffg_competitive {
            return Err(DoNotReOrg::JustificationAndFinalizationNotCompetitive.into());
        }

        // Compute re-org weight thresholds for head and parent.
        let re_org_head_weight_threshold =
            calculate_committee_fraction::<E>(justified_balances, re_org_head_threshold.0)
                .ok_or(Error::ReOrgThresholdOverflow)?;

        let re_org_parent_weight_threshold =
            calculate_committee_fraction::<E>(justified_balances, re_org_parent_threshold.0)
                .ok_or(Error::ReOrgThresholdOverflow)?;

        Ok(ProposerHeadInfo {
            head_node,
            parent_node,
            re_org_head_weight_threshold,
            re_org_parent_weight_threshold,
            current_slot,
        })
    }

    /// Returns `true` if there are any blocks in `self` with an `INVALID` execution payload status.
    ///
    /// This will operate on *all* blocks, even those that do not descend from the finalized
    /// ancestor.
    pub fn contains_invalid_payloads(&mut self) -> bool {
        self.proto_array.nodes.iter().any(|node| {
            node.execution_status()
                .is_ok_and(|status| status.is_invalid())
        })
    }

    /// For all nodes, regardless of their relationship to the finalized block, set their execution
    /// status to be optimistic.
    ///
    /// In practice this means forgetting any `VALID` or `INVALID` statuses.
    pub fn set_all_blocks_to_optimistic<E: EthSpec>(&mut self) -> Result<(), String> {
        // Iterate backwards through all nodes in the `proto_array`. Whilst it's not strictly
        // required to do this process in reverse, it seems natural when we consider how LMD votes
        // are counted.
        //
        // This function will touch all blocks, even those that do not descend from the finalized
        // block. Since this function is expected to run at start-up during very rare
        // circumstances we prefer simplicity over efficiency.
        for node_index in (0..self.proto_array.nodes.len()).rev() {
            let node = self
                .proto_array
                .nodes
                .get_mut(node_index)
                .ok_or("unreachable index out of bounds in proto_array nodes")?;

            match node.execution_status() {
                Ok(ExecutionStatus::Invalid(block_hash)) => {
                    if let ProtoNode::V17(node) = node {
                        node.execution_status = ExecutionStatus::Optimistic(block_hash);
                    }

                    // Restore the weight of the node, it would have been set to `0` in
                    // `apply_score_changes` when it was invalidated.
                    let restored_weight: u64 = self
                        .votes
                        .0
                        .iter()
                        .enumerate()
                        .filter_map(|(validator_index, vote)| {
                            if vote.current_root == node.root() {
                                // Any voting validator that does not have a balance should be
                                // ignored. This is consistent with `compute_deltas`.
                                self.balances.effective_balances.get(validator_index)
                            } else {
                                None
                            }
                        })
                        .sum();

                    // Add the restored weight to the node and all ancestors.
                    if restored_weight > 0 {
                        let mut node_or_ancestor = node;
                        loop {
                            *node_or_ancestor.weight_mut() = node_or_ancestor
                                .weight()
                                .checked_add(restored_weight)
                                .ok_or("Overflow when adding weight to ancestor")?;

                            if let Some(parent_index) = node_or_ancestor.parent() {
                                node_or_ancestor = self
                                    .proto_array
                                    .nodes
                                    .get_mut(parent_index)
                                    .ok_or(format!("Missing parent index: {}", parent_index))?;
                            } else {
                                // This is either the finalized block or a block that does not
                                // descend from the finalized block.
                                break;
                            }
                        }
                    }
                }
                // There are no balance changes required if the node was either valid or
                // optimistic.
                Ok(ExecutionStatus::Valid(block_hash))
                | Ok(ExecutionStatus::Optimistic(block_hash)) => {
                    if let ProtoNode::V17(node) = node {
                        node.execution_status = ExecutionStatus::Optimistic(block_hash)
                    }
                }
                // An irrelevant node cannot become optimistic, this is a no-op.
                Ok(ExecutionStatus::Irrelevant(_)) | Err(_) => (),
            }
        }

        Ok(())
    }

    pub fn maybe_prune(&mut self, finalized_root: Hash256) -> Result<(), String> {
        self.proto_array
            .maybe_prune(finalized_root)
            .map_err(|e| format!("find_head maybe_prune failed: {:?}", e))
    }

    pub fn set_prune_threshold(&mut self, prune_threshold: usize) {
        self.proto_array.prune_threshold = prune_threshold;
    }

    pub fn len(&self) -> usize {
        self.proto_array.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proto_array.nodes.is_empty()
    }

    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.proto_array.indices.contains_key(block_root)
    }

    fn get_proto_node(&self, block_root: &Hash256) -> Option<&ProtoNode> {
        let block_index = self.proto_array.indices.get(block_root)?;
        self.proto_array.nodes.get(*block_index)
    }

    pub fn get_block(&self, block_root: &Hash256) -> Option<Block> {
        let block = self.get_proto_node(block_root)?;
        let parent_root = block
            .parent()
            .and_then(|i| self.proto_array.nodes.get(i))
            .map(|parent| parent.root());

        Some(Block {
            slot: block.slot(),
            root: block.root(),
            parent_root,
            state_root: block.state_root(),
            target_root: block.target_root(),
            current_epoch_shuffling_id: block.current_epoch_shuffling_id().clone(),
            next_epoch_shuffling_id: block.next_epoch_shuffling_id().clone(),
            justified_checkpoint: *block.justified_checkpoint(),
            finalized_checkpoint: *block.finalized_checkpoint(),
            execution_status: block
                .execution_status()
                .unwrap_or_else(|_| ExecutionStatus::irrelevant()),
            unrealized_justified_checkpoint: block.unrealized_justified_checkpoint(),
            unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint(),
            execution_payload_parent_hash: block.execution_payload_parent_hash().ok(),
            execution_payload_block_hash: block.execution_payload_block_hash().ok(),
            proposer_index: block.proposer_index().ok(),
        })
    }

    /// Returns whether the proposer should extend the parent's execution payload chain.
    ///
    /// This checks timeliness, data availability, and proposer boost conditions per the spec.
    pub fn should_extend_payload<E: EthSpec>(
        &self,
        block_root: &Hash256,
        proposer_boost_root: Hash256,
    ) -> Result<bool, String> {
        let block_index = self
            .proto_array
            .indices
            .get(block_root)
            .ok_or_else(|| format!("Unknown block root: {block_root:?}"))?;
        let proto_node = self
            .proto_array
            .nodes
            .get(*block_index)
            .ok_or_else(|| format!("Missing node at index: {block_index}"))?;
        let fc_node = IndexedForkChoiceNode {
            root: proto_node.root(),
            proto_node_index: *block_index,
            payload_status: proto_node.get_parent_payload_status(),
        };
        self.proto_array
            .should_extend_payload::<E>(&fc_node, proto_node, proposer_boost_root)
            .map_err(|e| format!("{e:?}"))
    }

    /// Returns the `block.execution_status` field, if the block is present.
    pub fn get_block_execution_status(&self, block_root: &Hash256) -> Option<ExecutionStatus> {
        let block = self.get_proto_node(block_root)?;
        Some(
            block
                .execution_status()
                .unwrap_or_else(|_| ExecutionStatus::irrelevant()),
        )
    }

    /// Returns whether the execution payload for a block has been received.
    ///
    /// Returns `false` for pre-Gloas (V17) nodes or unknown blocks.
    pub fn is_payload_received(&self, block_root: &Hash256) -> bool {
        self.get_proto_node(block_root)
            .and_then(|node| node.payload_received().ok())
            .unwrap_or(false)
    }

    /// Returns the canonical payload status of a block, matching the decision
    /// `get_head` would make between `(root, FULL)` and `(root, EMPTY)`.
    pub fn get_canonical_payload_status<E: EthSpec>(
        &self,
        block_root: &Hash256,
        current_slot: Slot,
        proposer_boost_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<PayloadStatus, Error> {
        self.proto_array.get_canonical_payload_status::<E>(
            *block_root,
            current_slot,
            proposer_boost_root,
            &self.balances,
            spec,
        )
    }

    /// Returns the weight of a given block.
    pub fn get_weight(&self, block_root: &Hash256) -> Option<u64> {
        let block_index = self.proto_array.indices.get(block_root)?;
        self.proto_array
            .nodes
            .get(*block_index)
            .map(|node| node.weight())
    }

    /// Returns the payload status of the head node based on accumulated weights and tiebreaker.
    ///
    /// See `ProtoArray` documentation.
    pub fn is_descendant(&self, ancestor_root: Hash256, descendant_root: Hash256) -> bool {
        self.proto_array
            .is_descendant(ancestor_root, descendant_root)
    }

    /// See `ProtoArray` documentation.
    pub fn is_finalized_checkpoint_or_descendant<E: EthSpec>(
        &self,
        descendant_root: Hash256,
        best_finalized_checkpoint: Checkpoint,
    ) -> bool {
        self.proto_array
            .is_finalized_checkpoint_or_descendant::<E>(descendant_root, best_finalized_checkpoint)
    }

    /// NOTE: only used in tests.
    pub fn latest_message(&self, validator_index: usize) -> Option<LatestMessage> {
        if let Some(vote) = self.votes.0.get(validator_index) {
            if *vote == VoteTracker::default() {
                None
            } else {
                Some(LatestMessage {
                    root: vote.next_root,
                    slot: vote.next_slot,
                    payload_present: vote.next_payload_present,
                })
            }
        } else {
            None
        }
    }

    /// See `ProtoArray::iter_nodes`
    pub fn iter_nodes(&self, block_root: &Hash256) -> Iter<'_> {
        self.proto_array.iter_nodes(block_root)
    }

    /// See `ProtoArray::iter_block_roots`
    pub fn iter_block_roots(
        &self,
        block_root: &Hash256,
    ) -> impl Iterator<Item = (Hash256, Slot)> + '_ {
        self.proto_array.iter_block_roots(block_root)
    }

    pub fn as_ssz_container(&self) -> SszContainer {
        SszContainer::from_proto_array(self)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.as_ssz_container().as_ssz_bytes()
    }

    pub fn from_bytes(bytes: &[u8], balances: JustifiedBalances) -> Result<Self, String> {
        let container = SszContainer::from_ssz_bytes(bytes)
            .map_err(|e| format!("Failed to decode ProtoArrayForkChoice: {:?}", e))?;
        Self::from_container(container, balances)
    }

    pub fn from_container(
        container: SszContainer,
        balances: JustifiedBalances,
    ) -> Result<Self, String> {
        (container, balances)
            .try_into()
            .map_err(|e| format!("Failed to initialize ProtoArrayForkChoice: {e:?}"))
    }

    /// Returns a read-lock to core `ProtoArray` struct.
    ///
    /// Should only be used when encoding/decoding during troubleshooting.
    pub fn core_proto_array(&self) -> &ProtoArray {
        &self.proto_array
    }

    /// Returns a mutable reference to the core `ProtoArray` struct.
    ///
    /// Should only be used during database schema migrations.
    pub fn core_proto_array_mut(&mut self) -> &mut ProtoArray {
        &mut self.proto_array
    }

    /// Returns all nodes that have zero children and are descended from the finalized checkpoint.
    pub fn heads_descended_from_finalization<E: EthSpec>(
        &self,
        best_finalized_checkpoint: Checkpoint,
    ) -> Vec<&ProtoNode> {
        self.proto_array
            .heads_descended_from_finalization::<E>(best_finalized_checkpoint)
    }
}

/// Returns a list of `deltas`, where there is one delta for each of the indices in
/// `0..indices.len()`.
///
/// The deltas are formed by a change between `old_balances` and `new_balances`, and/or a change of vote in `votes`.
///
/// ## Errors
///
/// - If a value in `indices` is greater to or equal to `indices.len()`.
/// - If some `Hash256` in `votes` is not a key in `indices` (except for `Hash256::zero()`, this is
///   always valid).
fn compute_deltas(
    indices: &HashMap<Hash256, usize>,
    node_slots: &[Slot],
    votes: &mut ElasticList<VoteTracker>,
    old_balances: &[u64],
    new_balances: &[u64],
    equivocating_indices: &BTreeSet<u64>,
) -> Result<Vec<NodeDelta>, Error> {
    let block_slot = |index: usize| -> Result<Slot, Error> {
        node_slots
            .get(index)
            .copied()
            .ok_or(Error::InvalidNodeDelta(index))
    };

    let mut deltas = vec![
        NodeDelta {
            delta: 0,
            empty_delta: 0,
            full_delta: 0,
            equivocating_attestation_delta: 0,
        };
        indices.len()
    ];

    for (val_index, vote) in votes.iter_mut().enumerate() {
        // There is no need to create a score change if the validator has never voted or both their
        // votes are for the zero hash (alias to the genesis block).
        if vote.current_root == Hash256::zero() && vote.next_root == Hash256::zero() {
            continue;
        }

        // Handle newly slashed validators by deducting their weight from their current vote. We
        // determine if they are newly slashed by checking whether their `vote.current_root` is
        // non-zero. After applying the deduction a single time we set their `current_root` to zero
        // and never update it again (thus preventing repeat deductions).
        //
        // Even if they make new attestations which are processed by `process_attestation` these
        // will only update their `vote.next_root`.
        if equivocating_indices.contains(&(val_index as u64)) {
            // First time we've processed this slashing in fork choice:
            //
            // 1. Add a negative delta for their `current_root`.
            // 2. Set their `current_root` (permanently) to zero.
            if !vote.current_root.is_zero() {
                let old_balance = old_balances.get(val_index).copied().unwrap_or(0);

                if let Some(current_delta_index) = indices.get(&vote.current_root).copied() {
                    let node_delta = deltas
                        .get_mut(current_delta_index)
                        .ok_or(Error::InvalidNodeDelta(current_delta_index))?;
                    node_delta.delta = node_delta
                        .delta
                        .checked_sub(old_balance as i64)
                        .ok_or(Error::DeltaOverflow(current_delta_index))?;

                    let status = NodeDelta::payload_status(
                        vote.current_slot,
                        vote.current_payload_present,
                        block_slot(current_delta_index)?,
                    );
                    node_delta.sub_payload_delta(status, old_balance, current_delta_index)?;

                    // Track equivocating weight for `is_head_weak` monotonicity.
                    node_delta.equivocating_attestation_delta = node_delta
                        .equivocating_attestation_delta
                        .saturating_add(old_balance);
                }

                vote.current_root = Hash256::zero();
                vote.current_slot = Slot::new(0);
                vote.current_payload_present = false;
            }
            // We've handled this slashed validator, continue without applying an ordinary delta.
            continue;
        }

        // If the validator was not included in the _old_ balances (i.e., it did not exist yet)
        // then say its balance was zero.
        let old_balance = old_balances.get(val_index).copied().unwrap_or(0);

        // If the validators vote is not known in the _new_ balances, then use a balance of zero.
        //
        // It is possible that there is a vote for an unknown validator if we change our justified
        // state to a new state with a higher epoch that is on a different fork because that fork may have
        // on-boarded less validators than the prior fork.
        let new_balance = new_balances.get(val_index).copied().unwrap_or(0);

        if vote.current_root != vote.next_root
            || old_balance != new_balance
            || vote.current_payload_present != vote.next_payload_present
            || vote.current_slot != vote.next_slot
        {
            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(current_delta_index) = indices.get(&vote.current_root).copied() {
                let node_delta = deltas
                    .get_mut(current_delta_index)
                    .ok_or(Error::InvalidNodeDelta(current_delta_index))?;
                node_delta.delta = node_delta
                    .delta
                    .checked_sub(old_balance as i64)
                    .ok_or(Error::DeltaOverflow(current_delta_index))?;

                let status = NodeDelta::payload_status(
                    vote.current_slot,
                    vote.current_payload_present,
                    block_slot(current_delta_index)?,
                );
                node_delta.sub_payload_delta(status, old_balance, current_delta_index)?;
            }

            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(next_delta_index) = indices.get(&vote.next_root).copied() {
                let node_delta = deltas
                    .get_mut(next_delta_index)
                    .ok_or(Error::InvalidNodeDelta(next_delta_index))?;
                node_delta.delta = node_delta
                    .delta
                    .checked_add(new_balance as i64)
                    .ok_or(Error::DeltaOverflow(next_delta_index))?;

                let status = NodeDelta::payload_status(
                    vote.next_slot,
                    vote.next_payload_present,
                    block_slot(next_delta_index)?,
                );
                node_delta.add_payload_delta(status, new_balance, next_delta_index)?;
            }

            vote.current_root = vote.next_root;
            vote.current_slot = vote.next_slot;
            vote.current_payload_present = vote.next_payload_present;
        }
    }

    Ok(deltas)
}

#[cfg(test)]
mod test_compute_deltas {
    use super::*;
    use fixed_bytes::FixedBytesExtended;
    use types::MainnetEthSpec;

    /// Gives a hash that is not the zero hash (unless i is `usize::MAX)`.
    fn hash_from_index(i: usize) -> Hash256 {
        Hash256::from_low_u64_be(i as u64 + 1)
    }

    fn test_node_slots(count: usize) -> Vec<Slot> {
        vec![Slot::new(0); count]
    }

    #[test]
    fn finalized_descendant() {
        let spec = MainnetEthSpec::default_spec();
        let genesis_slot = Slot::new(0);
        let genesis_epoch = Epoch::new(0);

        let state_root = Hash256::from_low_u64_be(0);
        let finalized_root = Hash256::from_low_u64_be(1);
        let finalized_desc = Hash256::from_low_u64_be(2);
        let not_finalized_desc = Hash256::from_low_u64_be(3);
        let unknown = Hash256::from_low_u64_be(4);
        let junk_shuffling_id =
            AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());
        let execution_status = ExecutionStatus::irrelevant();

        let genesis_checkpoint = Checkpoint {
            epoch: genesis_epoch,
            root: finalized_root,
        };
        let junk_checkpoint = Checkpoint {
            epoch: Epoch::new(42),
            root: Hash256::repeat_byte(42),
        };

        let mut fc = ProtoArrayForkChoice::new::<MainnetEthSpec>(
            genesis_slot,
            genesis_slot,
            state_root,
            genesis_checkpoint,
            genesis_checkpoint,
            junk_shuffling_id.clone(),
            junk_shuffling_id.clone(),
            execution_status,
            None,
            None,
            0,
            &spec,
        )
        .unwrap();

        // Add block that is a finalized descendant.
        fc.proto_array
            .on_block::<MainnetEthSpec>(
                Block {
                    slot: genesis_slot + 1,
                    root: finalized_desc,
                    parent_root: Some(finalized_root),
                    state_root,
                    target_root: finalized_root,
                    current_epoch_shuffling_id: junk_shuffling_id.clone(),
                    next_epoch_shuffling_id: junk_shuffling_id.clone(),
                    justified_checkpoint: genesis_checkpoint,
                    finalized_checkpoint: genesis_checkpoint,
                    unrealized_justified_checkpoint: Some(genesis_checkpoint),
                    execution_status,
                    unrealized_finalized_checkpoint: Some(genesis_checkpoint),
                    execution_payload_parent_hash: None,
                    execution_payload_block_hash: None,
                    proposer_index: Some(0),
                },
                genesis_slot + 1,
                &spec,
                Duration::ZERO,
            )
            .unwrap();

        // Add block that is *not* a finalized descendant.
        fc.proto_array
            .on_block::<MainnetEthSpec>(
                Block {
                    slot: genesis_slot + 1,
                    root: not_finalized_desc,
                    parent_root: None,
                    state_root,
                    target_root: finalized_root,
                    current_epoch_shuffling_id: junk_shuffling_id.clone(),
                    next_epoch_shuffling_id: junk_shuffling_id,
                    // Use the junk checkpoint for the next to values to prevent
                    // the loop-shortcutting mechanism from triggering.
                    justified_checkpoint: junk_checkpoint,
                    finalized_checkpoint: junk_checkpoint,
                    execution_status,
                    unrealized_justified_checkpoint: None,
                    unrealized_finalized_checkpoint: None,
                    execution_payload_parent_hash: None,
                    execution_payload_block_hash: None,
                    proposer_index: Some(0),
                },
                genesis_slot + 1,
                &spec,
                Duration::ZERO,
            )
            .unwrap();

        assert!(!fc.is_descendant(unknown, unknown));
        assert!(!fc.is_descendant(unknown, finalized_root));
        assert!(!fc.is_descendant(unknown, finalized_desc));
        assert!(!fc.is_descendant(unknown, not_finalized_desc));

        assert!(fc.is_descendant(finalized_root, finalized_root));
        assert!(fc.is_descendant(finalized_root, finalized_desc));
        assert!(!fc.is_descendant(finalized_root, not_finalized_desc));
        assert!(!fc.is_descendant(finalized_root, unknown));

        assert!(fc.is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
            finalized_root,
            genesis_checkpoint
        ));
        assert!(fc.is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
            finalized_desc,
            genesis_checkpoint
        ));
        assert!(!fc.is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
            not_finalized_desc,
            genesis_checkpoint
        ));
        assert!(
            !fc.is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
                unknown,
                genesis_checkpoint
            )
        );

        assert!(!fc.is_descendant(finalized_desc, not_finalized_desc));
        assert!(fc.is_descendant(finalized_desc, finalized_desc));
        assert!(!fc.is_descendant(finalized_desc, finalized_root));
        assert!(!fc.is_descendant(finalized_desc, unknown));

        assert!(fc.is_descendant(not_finalized_desc, not_finalized_desc));
        assert!(!fc.is_descendant(not_finalized_desc, finalized_desc));
        assert!(!fc.is_descendant(not_finalized_desc, finalized_root));
        assert!(!fc.is_descendant(not_finalized_desc, unknown));
    }

    /// This test covers an interesting case where a block can be a descendant
    /// of the finalized *block*, but not a descenant of the finalized
    /// *checkpoint*.
    ///
    /// ## Example
    ///
    /// Consider this block tree which has three blocks (`A`, `B` and `C`):
    ///
    /// ```ignore
    /// [A] <--- [-] <--- [B]
    ///       |
    ///       |--[C]
    /// ```
    ///
    /// - `A` (slot 31) is the common descendant.
    /// - `B` (slot 33) descends from `A`, but there is a single skip slot
    ///   between it and `A`.
    /// - `C` (slot 32) descends from `A` and conflicts with `B`.
    ///
    /// Imagine that the `B` chain is finalized at epoch 1. This means that the
    /// finalized checkpoint points to the skipped slot at 32. The root of the
    /// finalized checkpoint is `A`.
    ///
    /// In this scenario, the block `C` has the finalized root (`A`) as an
    /// ancestor whilst simultaneously conflicting with the finalized
    /// checkpoint.
    ///
    /// This means that to ensure a block does not conflict with finality we
    /// must check to ensure that it's an ancestor of the finalized
    /// *checkpoint*, not just the finalized *block*.
    #[test]
    fn finalized_descendant_edge_case() {
        let spec = MainnetEthSpec::default_spec();
        let get_block_root = Hash256::from_low_u64_be;
        let genesis_slot = Slot::new(0);
        let junk_state_root = Hash256::zero();
        let junk_shuffling_id =
            AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());
        let execution_status = ExecutionStatus::irrelevant();

        let genesis_checkpoint = Checkpoint {
            epoch: Epoch::new(0),
            root: get_block_root(0),
        };

        let mut fc = ProtoArrayForkChoice::new::<MainnetEthSpec>(
            genesis_slot,
            genesis_slot,
            junk_state_root,
            genesis_checkpoint,
            genesis_checkpoint,
            junk_shuffling_id.clone(),
            junk_shuffling_id.clone(),
            execution_status,
            None,
            None,
            0,
            &spec,
        )
        .unwrap();

        struct TestBlock {
            slot: u64,
            root: u64,
            parent_root: u64,
        }

        let insert_block = |fc: &mut ProtoArrayForkChoice, block: TestBlock| {
            fc.proto_array
                .on_block::<MainnetEthSpec>(
                    Block {
                        slot: Slot::from(block.slot),
                        root: get_block_root(block.root),
                        parent_root: Some(get_block_root(block.parent_root)),
                        state_root: Hash256::zero(),
                        target_root: Hash256::zero(),
                        current_epoch_shuffling_id: junk_shuffling_id.clone(),
                        next_epoch_shuffling_id: junk_shuffling_id.clone(),
                        justified_checkpoint: Checkpoint {
                            epoch: Epoch::new(0),
                            root: get_block_root(0),
                        },
                        finalized_checkpoint: genesis_checkpoint,
                        execution_status,
                        unrealized_justified_checkpoint: Some(genesis_checkpoint),
                        unrealized_finalized_checkpoint: Some(genesis_checkpoint),
                        execution_payload_parent_hash: None,
                        execution_payload_block_hash: None,
                        proposer_index: Some(0),
                    },
                    Slot::from(block.slot),
                    &spec,
                    Duration::ZERO,
                )
                .unwrap();
        };

        /*
         * Start of interesting part of tests.
         */

        // Produce the 0th epoch of blocks. They should all form a chain from
        // the genesis block.
        for i in 1..MainnetEthSpec::slots_per_epoch() {
            insert_block(
                &mut fc,
                TestBlock {
                    slot: i,
                    root: i,
                    parent_root: i - 1,
                },
            )
        }

        let last_slot_of_epoch_0 = MainnetEthSpec::slots_per_epoch() - 1;

        // Produce a block that descends from the last block of epoch -.
        //
        // This block will be non-canonical.
        let non_canonical_slot = last_slot_of_epoch_0 + 1;
        insert_block(
            &mut fc,
            TestBlock {
                slot: non_canonical_slot,
                root: non_canonical_slot,
                parent_root: non_canonical_slot - 1,
            },
        );

        // Produce a block that descends from the last block of the 0th epoch,
        // that skips the 1st slot of the 1st epoch.
        //
        // This block will be canonical.
        let canonical_slot = last_slot_of_epoch_0 + 2;
        insert_block(
            &mut fc,
            TestBlock {
                slot: canonical_slot,
                root: canonical_slot,
                parent_root: non_canonical_slot - 1,
            },
        );

        let finalized_root = get_block_root(last_slot_of_epoch_0);

        // Set the finalized checkpoint to finalize the first slot of epoch 1 on
        // the canonical chain.
        let finalized_checkpoint = Checkpoint {
            root: finalized_root,
            epoch: Epoch::new(1),
        };

        assert!(
            fc.proto_array
                .is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
                    finalized_root,
                    finalized_checkpoint
                ),
            "the finalized checkpoint is the finalized checkpoint"
        );

        assert!(
            fc.proto_array
                .is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
                    get_block_root(canonical_slot),
                    finalized_checkpoint
                ),
            "the canonical block is a descendant of the finalized checkpoint"
        );
        assert!(
            !fc.proto_array
                .is_finalized_checkpoint_or_descendant::<MainnetEthSpec>(
                    get_block_root(non_canonical_slot),
                    finalized_checkpoint
                ),
            "although the non-canonical block is a descendant of the finalized block, \
            it's not a descendant of the finalized checkpoint"
        );
    }

    #[test]
    fn zero_hash() {
        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: Hash256::zero(),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
            old_balances.push(0);
            new_balances.push(0);
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );
        assert_eq!(
            deltas,
            vec![0; validator_count],
            "deltas should all be zero"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn all_voted_the_same() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(0),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    BALANCE as i64 * validator_count as i64,
                    "zero'th root should have a delta"
                );
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn different_votes() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(i),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for delta in deltas.into_iter() {
            assert_eq!(
                delta, BALANCE as i64,
                "each root should have the same delta"
            );
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn moving_votes() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        let total_delta = BALANCE as i64 * validator_count as i64;

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    0 - total_delta,
                    "zero'th root should have a negative delta"
                );
            } else if i == 1 {
                assert_eq!(delta, total_delta, "first root should have positive delta");
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn move_out_of_tree() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There is only one block.
        indices.insert(hash_from_index(1), 0);

        // There are two validators.
        let old_balances = vec![BALANCE; 2];
        let new_balances = vec![BALANCE; 2];

        // One validator moves their vote from the block to the zero hash.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::zero(),
            current_slot: Slot::new(0),
            next_slot: Slot::new(0),
            current_payload_present: false,
            next_payload_present: false,
        });

        // One validator moves their vote from the block to something outside the tree.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::from_low_u64_be(1337),
            current_slot: Slot::new(0),
            next_slot: Slot::new(0),
            current_payload_present: false,
            next_payload_present: false,
        });

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 1, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64 * 2,
            "the block should have lost both balances"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn changing_balances() {
        const OLD_BALANCE: u64 = 42;
        const NEW_BALANCE: u64 = OLD_BALANCE * 2;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
            old_balances.push(OLD_BALANCE);
            new_balances.push(NEW_BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    0 - OLD_BALANCE as i64 * validator_count as i64,
                    "zero'th root should have a negative delta"
                );
            } else if i == 1 {
                assert_eq!(
                    delta,
                    NEW_BALANCE as i64 * validator_count as i64,
                    "first root should have positive delta"
                );
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn validator_appears() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There is only one validator in the old balances.
        let old_balances = vec![BALANCE; 1];
        // There are two validators in the new balances.
        let new_balances = vec![BALANCE; 2];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64,
            "block 1 should have only lost one balance"
        );
        assert_eq!(
            deltas[1],
            2 * BALANCE as i64,
            "block 2 should have gained two balances"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn validator_disappears() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There are two validators in the old balances.
        let old_balances = vec![BALANCE; 2];
        // There is only one validator in the new balances.
        let new_balances = vec![BALANCE; 1];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
        }

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64 * 2,
            "block 1 should have lost both balances"
        );
        assert_eq!(
            deltas[1], BALANCE as i64,
            "block 2 should have only gained one balance"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote should have been updated"
            );
        }
    }

    #[test]
    fn validator_equivocates() {
        const OLD_BALANCE: u64 = 42;
        const NEW_BALANCE: u64 = 43;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There are two validators.
        let old_balances = vec![OLD_BALANCE; 2];
        let new_balances = vec![NEW_BALANCE; 2];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                current_slot: Slot::new(0),
                next_slot: Slot::new(0),
                current_payload_present: false,
                next_payload_present: false,
            });
        }

        // Validator 0 is slashed.
        let equivocating_indices = BTreeSet::from_iter([0]);

        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            -2 * OLD_BALANCE as i64,
            "block 1 should have lost two old balances"
        );
        assert_eq!(
            deltas[1], NEW_BALANCE as i64,
            "block 2 should have gained one balance"
        );

        // Validator 0's current root should have been reset.
        assert_eq!(votes.0[0].current_root, Hash256::zero());
        assert_eq!(votes.0[0].next_root, hash_from_index(2));

        // Validator 1's current root should have been updated.
        assert_eq!(votes.0[1].current_root, hash_from_index(2));

        // Re-computing the deltas should be a no-op (no repeat deduction for the slashed validator).
        let deltas = compute_deltas(
            &indices,
            &test_node_slots(indices.len()),
            &mut votes,
            &new_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");
        assert_eq!(deltas, vec![0, 0]);
    }

    #[test]
    fn payload_bucket_changes_on_non_pending_vote() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        indices.insert(hash_from_index(1), 0);

        let node_slots = vec![Slot::new(0)];
        let mut votes = ElasticList(vec![VoteTracker {
            current_root: hash_from_index(1),
            next_root: hash_from_index(1),
            current_slot: Slot::new(1),
            next_slot: Slot::new(1),
            current_payload_present: false,
            next_payload_present: true,
        }]);

        let deltas = compute_deltas(
            &indices,
            &node_slots,
            &mut votes,
            &[BALANCE],
            &[BALANCE],
            &BTreeSet::new(),
        )
        .expect("should compute deltas");

        assert_eq!(deltas[0].delta, 0);
        assert_eq!(deltas[0].empty_delta, -(BALANCE as i64));
        assert_eq!(deltas[0].full_delta, BALANCE as i64);
    }

    #[test]
    fn pending_vote_only_updates_regular_weight() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        indices.insert(hash_from_index(1), 0);

        let node_slots = vec![Slot::new(0)];
        let mut votes = ElasticList(vec![VoteTracker {
            current_root: hash_from_index(1),
            next_root: hash_from_index(1),
            current_slot: Slot::new(0),
            next_slot: Slot::new(0),
            current_payload_present: false,
            next_payload_present: true,
        }]);

        let deltas = compute_deltas(
            &indices,
            &node_slots,
            &mut votes,
            &[BALANCE],
            &[BALANCE],
            &BTreeSet::new(),
        )
        .expect("should compute deltas");

        assert_eq!(deltas[0].delta, 0);
        assert_eq!(deltas[0].empty_delta, 0);
        assert_eq!(deltas[0].full_delta, 0);
    }
}
