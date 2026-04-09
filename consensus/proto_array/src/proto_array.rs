use crate::error::InvalidBestNodeInfo;
use crate::proto_array_fork_choice::IndexedForkChoiceNode;
use crate::{
    Block, ExecutionStatus, JustifiedBalances, LatestMessage, PayloadStatus, error::Error,
};
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use ssz::Encode;
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use superstruct::superstruct;
use typenum::U512;
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    Slot,
};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

fn all_true_bitvector<N: typenum::Unsigned + Clone>() -> BitVector<N> {
    let mut bv = BitVector::new();
    for i in 0..bv.len() {
        let _ = bv.set(i, true);
    }
    bv
}

/// Defines an operation which may invalidate the `execution_status` of some nodes.
#[derive(Clone, Debug)]
pub enum InvalidationOperation {
    /// Invalidate only `block_root` and it's descendants. Don't invalidate any ancestors.
    InvalidateOne { block_root: Hash256 },
    /// Invalidate blocks between `head_block_root` and `latest_valid_ancestor`.
    ///
    /// If the `latest_valid_ancestor` is known to fork choice, invalidate all blocks between
    /// `head_block_root` and `latest_valid_ancestor`. The `head_block_root` will be invalidated,
    /// whilst the `latest_valid_ancestor` will not.
    ///
    /// If `latest_valid_ancestor` is *not* known to fork choice, only invalidate the
    /// `head_block_root` if `always_invalidate_head == true`.
    InvalidateMany {
        head_block_root: Hash256,
        always_invalidate_head: bool,
        latest_valid_ancestor: ExecutionBlockHash,
    },
}

impl InvalidationOperation {
    pub fn block_root(&self) -> Hash256 {
        match self {
            InvalidationOperation::InvalidateOne { block_root } => *block_root,
            InvalidationOperation::InvalidateMany {
                head_block_root, ..
            } => *head_block_root,
        }
    }

    pub fn latest_valid_ancestor(&self) -> Option<ExecutionBlockHash> {
        match self {
            InvalidationOperation::InvalidateOne { .. } => None,
            InvalidationOperation::InvalidateMany {
                latest_valid_ancestor,
                ..
            } => Some(*latest_valid_ancestor),
        }
    }

    pub fn invalidate_block_root(&self) -> bool {
        match self {
            InvalidationOperation::InvalidateOne { .. } => true,
            InvalidationOperation::InvalidateMany {
                always_invalidate_head,
                ..
            } => *always_invalidate_head,
        }
    }
}

#[superstruct(
    variants(V17, V29),
    variant_attributes(derive(Clone, PartialEq, Debug, Encode, Decode, Serialize, Deserialize))
)]
#[derive(PartialEq, Debug, Encode, Decode, Serialize, Deserialize, Clone)]
#[ssz(enum_behaviour = "union")]
pub struct ProtoNode {
    /// The `slot` is not necessary for `ProtoArray`, it just exists so external components can
    /// easily query the block slot. This is useful for upstream fork choice logic.
    #[superstruct(getter(copy))]
    pub slot: Slot,
    /// The `state_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely attestation verification).
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    /// The root that would be used for the `attestation.data.target.root` if a LMD vote was cast
    /// for this block.
    ///
    /// The `target_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely fork choice attestation verification).
    #[superstruct(getter(copy))]
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    #[superstruct(getter(copy))]
    pub root: Hash256,
    #[superstruct(getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    #[superstruct(only(V17, V29), partial_getter(copy))]
    pub justified_checkpoint: Checkpoint,
    #[superstruct(only(V17, V29), partial_getter(copy))]
    pub finalized_checkpoint: Checkpoint,
    #[superstruct(getter(copy))]
    pub weight: u64,
    #[superstruct(only(V17), partial_getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub best_child: Option<usize>,
    #[superstruct(only(V17), partial_getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub best_descendant: Option<usize>,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash. This is only used pre-Gloas.
    #[superstruct(only(V17), partial_getter(copy))]
    pub execution_status: ExecutionStatus,
    #[superstruct(getter(copy))]
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    #[superstruct(getter(copy))]
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,

    /// We track the parent payload status from which the current node was extended.
    #[superstruct(only(V29), partial_getter(copy))]
    pub parent_payload_status: PayloadStatus,
    #[superstruct(only(V29), partial_getter(copy))]
    pub empty_payload_weight: u64,
    #[superstruct(only(V29), partial_getter(copy))]
    pub full_payload_weight: u64,
    #[superstruct(only(V29), partial_getter(copy))]
    pub execution_payload_block_hash: ExecutionBlockHash,
    #[superstruct(only(V29), partial_getter(copy))]
    pub execution_payload_parent_hash: ExecutionBlockHash,
    /// Equivalent to spec's `block_timeliness[root][ATTESTATION_TIMELINESS_INDEX]`.
    #[superstruct(only(V29), partial_getter(copy))]
    pub block_timeliness_attestation_threshold: bool,
    /// Equivalent to spec's `block_timeliness[root][PTC_TIMELINESS_INDEX]`.
    #[superstruct(only(V29), partial_getter(copy))]
    pub block_timeliness_ptc_threshold: bool,
    /// Equivalent to spec's `store.payload_timeliness_vote[root]`.
    /// PTC timeliness vote bitfield, indexed by PTC committee position.
    /// Bit i set means PTC member i voted `payload_present = true`.
    /// Tiebreak derived as: `num_set_bits() > ptc_size / 2`.
    #[superstruct(only(V29))]
    pub payload_timeliness_votes: BitVector<U512>,
    /// Equivalent to spec's `store.payload_data_availability_vote[root]`.
    /// PTC data availability vote bitfield, indexed by PTC committee position.
    /// Bit i set means PTC member i voted `blob_data_available = true`.
    /// Tiebreak derived as: `num_set_bits() > ptc_size / 2`.
    #[superstruct(only(V29))]
    pub payload_data_availability_votes: BitVector<U512>,
    /// Whether the execution payload for this block has been received and validated locally.
    /// Maps to `root in store.payload_states` in the spec.
    #[superstruct(only(V29), partial_getter(copy))]
    pub payload_received: bool,
    /// The proposer index for this block, used by `should_apply_proposer_boost`
    /// to detect equivocations at the parent's slot.
    #[superstruct(only(V29), partial_getter(copy))]
    pub proposer_index: u64,
    /// Weight from equivocating validators that voted for this block.
    /// Used by `is_head_weak` to match the spec's monotonicity guarantee:
    /// more attestations can only increase head weight, never decrease it.
    #[superstruct(only(V29), partial_getter(copy))]
    pub equivocating_attestation_score: u64,
}

impl ProtoNode {
    /// Generic version of spec's `parent_payload_status` that works for pre-Gloas nodes by
    /// considering their parents Empty.
    pub fn get_parent_payload_status(&self) -> PayloadStatus {
        self.parent_payload_status().unwrap_or(PayloadStatus::Empty)
    }

    pub fn is_parent_node_full(&self) -> bool {
        self.get_parent_payload_status() == PayloadStatus::Full
    }

    pub fn attestation_score(&self, payload_status: PayloadStatus) -> u64 {
        match payload_status {
            PayloadStatus::Pending => self.weight(),
            // Pre-Gloas (V17) nodes have no payload separation — all weight
            // is in `weight()`. Post-Gloas (V29) nodes track per-status weights.
            PayloadStatus::Empty => self
                .empty_payload_weight()
                .unwrap_or_else(|_| self.weight()),
            PayloadStatus::Full => self.full_payload_weight().unwrap_or_else(|_| self.weight()),
        }
    }

    pub fn is_payload_timely<E: EthSpec>(&self) -> bool {
        let Ok(node) = self.as_v29() else {
            return false;
        };

        // Equivalent to `if root not in store.payload_states` in the spec.
        if !node.payload_received {
            return false;
        }

        node.payload_timeliness_votes.num_set_bits() > E::ptc_size() / 2
    }

    pub fn is_payload_data_available<E: EthSpec>(&self) -> bool {
        let Ok(node) = self.as_v29() else {
            return false;
        };

        // Equivalent to `if root not in store.payload_states` in the spec.
        if !node.payload_received {
            return false;
        }

        // TODO(gloas): add function on EthSpec for DATA_AVAILABILITY_TIMELY_THRESHOLD
        node.payload_data_availability_votes.num_set_bits() > E::ptc_size() / 2
    }
}

#[derive(PartialEq, Debug, Encode, Decode, Serialize, Deserialize, Copy, Clone)]
pub struct ProposerBoost {
    pub root: Hash256,
    pub score: u64,
}

impl Default for ProposerBoost {
    fn default() -> Self {
        Self {
            root: Hash256::zero(),
            score: 0,
        }
    }
}

/// Accumulated score changes for a single proto-array node during a `find_head` pass.
///
/// `delta` tracks the ordinary LMD-GHOST balance change applied to the concrete block node.
/// This is the same notion of weight that pre-gloas fork choice used.
///
///
/// Under gloas we also need to track how votes contribute to the parent's virtual payload
/// branches:
///
/// - `empty_delta` is the balance change attributable to votes that support the `Empty` payload
///   interpretation of the node
/// - `full_delta` is the balance change attributable to votes that support the `Full` payload
///   interpretation of the node
///
/// Votes in `Pending` state only affect `delta`; they do not contribute to either payload bucket.
/// During score application these payload deltas are propagated independently up the tree so that
/// ancestors can compare children using payload-aware tie breaking.
#[derive(Clone, PartialEq, Debug, Copy)]
pub struct NodeDelta {
    /// Total weight change for the node. All votes contribute regardless of payload status.
    pub delta: i64,
    /// Weight change from `PayloadStatus::Empty` votes.
    pub empty_delta: i64,
    /// Weight change from `PayloadStatus::Full` votes.
    pub full_delta: i64,
    /// Weight from equivocating validators that voted for this node.
    pub equivocating_attestation_delta: u64,
}

impl NodeDelta {
    /// Classify a vote into the payload bucket it contributes to for `block_slot`.
    ///
    /// Per the gloas model:
    ///
    /// - a same-slot vote is `Pending`
    /// - a later vote with `payload_present = true` is `Full`
    /// - a later vote with `payload_present = false` is `Empty`
    ///
    /// This classification is used only for payload-aware accounting; all votes still contribute to
    /// the aggregate `delta`.
    pub fn payload_status(
        vote_slot: Slot,
        payload_present: bool,
        block_slot: Slot,
    ) -> PayloadStatus {
        if vote_slot == block_slot {
            PayloadStatus::Pending
        } else if payload_present {
            PayloadStatus::Full
        } else {
            PayloadStatus::Empty
        }
    }

    /// Add `balance` to the payload bucket selected by `status`.
    ///
    /// `Pending` votes do not affect payload buckets, so this becomes a no-op for that case.
    pub fn add_payload_delta(
        &mut self,
        status: PayloadStatus,
        balance: u64,
        index: usize,
    ) -> Result<(), Error> {
        let field = match status {
            PayloadStatus::Full => &mut self.full_delta,
            PayloadStatus::Empty => &mut self.empty_delta,
            PayloadStatus::Pending => return Ok(()),
        };
        *field = field
            .checked_add(balance as i64)
            .ok_or(Error::DeltaOverflow(index))?;
        Ok(())
    }

    /// Create a delta that only affects the aggregate block weight.
    ///
    /// This is useful for callers or tests that only care about ordinary LMD-GHOST weight changes
    /// and do not need payload-aware accounting.
    pub fn from_delta(delta: i64) -> Self {
        Self {
            delta,
            empty_delta: 0,
            full_delta: 0,
            equivocating_attestation_delta: 0,
        }
    }

    /// Subtract `balance` from the payload bucket selected by `status`.
    ///
    /// `Pending` votes do not affect payload buckets, so this becomes a no-op for that case.
    pub fn sub_payload_delta(
        &mut self,
        status: PayloadStatus,
        balance: u64,
        index: usize,
    ) -> Result<(), Error> {
        let field = match status {
            PayloadStatus::Full => &mut self.full_delta,
            PayloadStatus::Empty => &mut self.empty_delta,
            PayloadStatus::Pending => return Ok(()),
        };
        *field = field
            .checked_sub(balance as i64)
            .ok_or(Error::DeltaOverflow(index))?;
        Ok(())
    }
}

/// Compare NodeDelta with i64 by comparing the aggregate `delta` field.
/// This is used by tests that only care about the total weight delta.
impl PartialEq<i64> for NodeDelta {
    fn eq(&self, other: &i64) -> bool {
        self.delta == *other
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ProtoArray {
    /// Do not attempt to prune the tree unless it has at least this many nodes. Small prunes
    /// simply waste time.
    pub prune_threshold: usize,
    pub nodes: Vec<ProtoNode>,
    pub indices: HashMap<Hash256, usize>,
}

impl ProtoArray {
    /// Iterate backwards through the array, touching all nodes and their parents and potentially
    /// the best-child of each parent.
    ///
    /// The structure of the `self.nodes` array ensures that the child of each node is always
    /// touched before its parent.
    ///
    /// For each node, the following is done:
    ///
    /// - Update the node's weight with the corresponding delta.
    /// - Back-propagate each node's delta to its parents delta.
    /// - Compare the current node with the parents best-child, updating it if the current node
    ///   should become the best child.
    /// - If required, update the parents best-descendant with the current node or its best-descendant.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_score_changes<E: EthSpec>(
        &mut self,
        mut deltas: Vec<NodeDelta>,
    ) -> Result<(), Error> {
        if deltas.len() != self.indices.len() {
            return Err(Error::InvalidDeltaLen {
                deltas: deltas.len(),
                indices: self.indices.len(),
            });
        }

        // Iterate backwards through all indices in `self.nodes`.
        for node_index in (0..self.nodes.len()).rev() {
            let node = self
                .nodes
                .get_mut(node_index)
                .ok_or(Error::InvalidNodeIndex(node_index))?;

            // There is no need to adjust the balances or manage parent of the zero hash since it
            // is an alias to the genesis block. The weight applied to the genesis block is
            // irrelevant as we _always_ choose it and it's impossible for it to have a parent.
            if node.root() == Hash256::zero() {
                continue;
            }

            let execution_status_is_invalid = if let Ok(proto_node) = node.as_v17()
                && proto_node.execution_status.is_invalid()
            {
                true
            } else {
                false
            };

            let node_delta = deltas
                .get(node_index)
                .copied()
                .ok_or(Error::InvalidNodeDelta(node_index))?;

            let delta = if execution_status_is_invalid {
                // If the node has an invalid execution payload, reduce its weight to zero.
                0_i64
                    .checked_sub(node.weight() as i64)
                    .ok_or(Error::InvalidExecutionDeltaOverflow(node_index))?
            } else {
                node_delta.delta
            };

            let (node_empty_delta, node_full_delta) = if node.as_v29().is_ok() {
                (node_delta.empty_delta, node_delta.full_delta)
            } else {
                (0, 0)
            };

            // Proposer boost is NOT applied here. It is computed on-the-fly
            // during the virtual tree walk in `get_weight`, matching the spec's
            // `get_weight` which adds boost separately from `get_attestation_score`.

            // Apply the delta to the node.
            if execution_status_is_invalid {
                // Invalid nodes always have a weight of 0.
                *node.weight_mut() = 0;
            } else {
                *node.weight_mut() = apply_delta(node.weight(), delta, node_index)?;
            }

            // Apply post-Gloas score deltas.
            if let Ok(node) = node.as_v29_mut() {
                node.empty_payload_weight =
                    apply_delta(node.empty_payload_weight, node_empty_delta, node_index)?;
                node.full_payload_weight =
                    apply_delta(node.full_payload_weight, node_full_delta, node_index)?;
                node.equivocating_attestation_score = node
                    .equivocating_attestation_score
                    .saturating_add(node_delta.equivocating_attestation_delta);
            }

            // Update the parent delta (if any).
            if let Some(parent_index) = node.parent() {
                let parent_delta = deltas
                    .get_mut(parent_index)
                    .ok_or(Error::InvalidParentDelta(parent_index))?;

                // Back-propagate the node's delta to its parent.
                parent_delta.delta = parent_delta
                    .delta
                    .checked_add(delta)
                    .ok_or(Error::DeltaOverflow(parent_index))?;

                // Route ALL child weight into the parent's FULL or EMPTY bucket
                // based on the child's `parent_payload_status` (the ancestor path
                // direction). If this child is on the FULL path from the parent,
                // all weight supports the parent's FULL virtual node, and vice versa.
                if let Ok(child_v29) = node.as_v29() {
                    if child_v29.parent_payload_status == PayloadStatus::Full {
                        parent_delta.full_delta = parent_delta
                            .full_delta
                            .checked_add(delta)
                            .ok_or(Error::DeltaOverflow(parent_index))?;
                    } else {
                        parent_delta.empty_delta = parent_delta
                            .empty_delta
                            .checked_add(delta)
                            .ok_or(Error::DeltaOverflow(parent_index))?;
                    }
                } else {
                    // This is a v17 node with a v17 parent.
                    // There is no empty or full weight for v17 nodes, so nothing to propagate.
                    // In the tree walk, the v17 nodes have an empty child with 0 weight, which
                    // wins by default (it is the only child).
                }
            }
        }

        Ok(())
    }

    /// Register a block with the fork choice.
    ///
    /// It is only sane to supply a `None` parent for the genesis block.
    pub fn on_block<E: EthSpec>(
        &mut self,
        block: Block,
        current_slot: Slot,
        spec: &ChainSpec,
        time_into_slot: Duration,
    ) -> Result<(), Error> {
        // If the block is already known, simply ignore it.
        if self.indices.contains_key(&block.root) {
            return Ok(());
        }

        // We do not allow `proposer_index=None` for calls to `on_block`, it is only non-optional
        // for backwards-compatibility with pre-Gloas V17 proto nodes.
        let Some(proposer_index) = block.proposer_index else {
            return Err(Error::OnBlockRequiresProposerIndex);
        };

        let node_index = self.nodes.len();

        let parent_index = block
            .parent_root
            .and_then(|parent| self.indices.get(&parent).copied());

        let node = if !spec.fork_name_at_slot::<E>(block.slot).gloas_enabled() {
            ProtoNode::V17(ProtoNodeV17 {
                slot: block.slot,
                root: block.root,
                target_root: block.target_root,
                current_epoch_shuffling_id: block.current_epoch_shuffling_id,
                next_epoch_shuffling_id: block.next_epoch_shuffling_id,
                state_root: block.state_root,
                parent: parent_index,
                justified_checkpoint: block.justified_checkpoint,
                finalized_checkpoint: block.finalized_checkpoint,
                weight: 0,
                best_child: None,
                best_descendant: None,
                execution_status: block.execution_status,
                unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
                unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint,
            })
        } else {
            let is_current_slot = current_slot == block.slot;

            let execution_payload_block_hash =
                block
                    .execution_payload_block_hash
                    .ok_or(Error::BrokenBlock {
                        block_root: block.root,
                    })?;

            let execution_payload_parent_hash =
                block
                    .execution_payload_parent_hash
                    .ok_or(Error::BrokenBlock {
                        block_root: block.root,
                    })?;

            let parent_payload_status: PayloadStatus =
                if let Some(parent_node) = parent_index.and_then(|idx| self.nodes.get(idx)) {
                    match parent_node {
                        ProtoNode::V29(v29) => {
                            // Both parent and child are Gloas blocks. The parent is full if the
                            // block hash in the parent node matches the parent block hash in the
                            // child bid.
                            if execution_payload_parent_hash == v29.execution_payload_block_hash {
                                PayloadStatus::Full
                            } else {
                                PayloadStatus::Empty
                            }
                        }
                        ProtoNode::V17(_) => {
                            // Parent is pre-Gloas, pre-Gloas blocks are treated as having Empty
                            // payload status. This case is reached during the fork transition.
                            PayloadStatus::Empty
                        }
                    }
                } else {
                    // TODO(gloas): re-assess this assumption
                    // Parent is missing (genesis or pruned due to finalization). Default to Full
                    // since this path should only be hit at Gloas genesis.
                    PayloadStatus::Full
                };

            // Per spec `get_forkchoice_store`: the anchor (genesis) block has
            // its payload state initialized (`payload_states = {anchor_root: ...}`).
            // Without `payload_received = true` on genesis, the FULL virtual
            // child doesn't exist in the spec's `get_node_children`, making all
            // Full concrete children of genesis unreachable in `get_head`.
            let is_genesis = parent_index.is_none();

            ProtoNode::V29(ProtoNodeV29 {
                slot: block.slot,
                root: block.root,
                target_root: block.target_root,
                current_epoch_shuffling_id: block.current_epoch_shuffling_id,
                next_epoch_shuffling_id: block.next_epoch_shuffling_id,
                state_root: block.state_root,
                parent: parent_index,
                justified_checkpoint: block.justified_checkpoint,
                finalized_checkpoint: block.finalized_checkpoint,
                weight: 0,
                unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
                unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint,
                parent_payload_status,
                empty_payload_weight: 0,
                full_payload_weight: 0,
                execution_payload_block_hash,
                execution_payload_parent_hash,
                // Per spec `get_forkchoice_store`: the anchor block's PTC votes are
                // initialized to all-True, ensuring `is_payload_timely` and
                // `is_payload_data_available` return true for the anchor.
                payload_timeliness_votes: if is_genesis {
                    all_true_bitvector()
                } else {
                    BitVector::default()
                },
                payload_data_availability_votes: if is_genesis {
                    all_true_bitvector()
                } else {
                    BitVector::default()
                },
                payload_received: is_genesis,
                proposer_index,
                // Spec: `record_block_timeliness` + `get_forkchoice_store`.
                // Anchor gets [True, True]. Others computed from time_into_slot.
                block_timeliness_attestation_threshold: is_genesis
                    || (is_current_slot
                        && time_into_slot < spec.get_attestation_due::<E>(current_slot)),
                block_timeliness_ptc_threshold: is_genesis
                    || (is_current_slot && time_into_slot < spec.get_payload_attestation_due()),
                equivocating_attestation_score: 0,
            })
        };

        // If the parent has an invalid execution status, return an error before adding the
        // block to `self`. This applies only when the parent is a V17 node with execution tracking.
        if let Some(parent_index) = node.parent() {
            let parent = self
                .nodes
                .get(parent_index)
                .ok_or(Error::InvalidNodeIndex(parent_index))?;

            // Execution status tracking only exists on V17 (pre-Gloas) nodes.
            if let Ok(v17) = parent.as_v17()
                && v17.execution_status.is_invalid()
            {
                return Err(Error::ParentExecutionStatusIsInvalid {
                    block_root: block.root,
                    parent_root: parent.root(),
                });
            }
        }

        self.indices.insert(node.root(), node_index);
        self.nodes.push(node.clone());

        if let Some(parent_index) = node.parent()
            && matches!(block.execution_status, ExecutionStatus::Valid(_))
        {
            self.propagate_execution_payload_validation_by_index(parent_index)?;
        }

        Ok(())
    }

    /// Spec: `is_head_weak`.
    // TODO(gloas): the spec adds weight from equivocating validators in the
    // head slot's *committees*, regardless of who they voted for. We approximate
    // with `equivocating_attestation_score` which only tracks equivocating
    // validators whose vote pointed at this block. This under-counts when an
    // equivocating validator is in the committee but voted for a different fork,
    // which could allow a re-org the spec wouldn't. In practice the deviation
    // is small — it requires equivocating validators voting for competing forks
    // AND the head weight to be exactly at the reorg threshold boundary.
    // Fixing this properly requires committee computation from BeaconState,
    // which is not available in proto_array. The fix would be to pass
    // pre-computed equivocating committee weight from the beacon_chain caller.
    fn is_head_weak<E: EthSpec>(
        &self,
        head_node: &ProtoNode,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> bool {
        let reorg_threshold = calculate_committee_fraction::<E>(
            justified_balances,
            spec.reorg_head_weight_threshold.unwrap_or(20),
        )
        .unwrap_or(0);

        let head_weight = head_node
            .attestation_score(PayloadStatus::Pending)
            .saturating_add(head_node.equivocating_attestation_score().unwrap_or(0));

        head_weight < reorg_threshold
    }

    /// Spec's `should_apply_proposer_boost` for Gloas.
    ///
    /// Returns `true` if the proposer boost should be kept. Returns `false` if the
    /// boost should be subtracted (invalidated) because the parent is weak and there
    /// are no equivocating blocks at the parent's slot.
    fn should_apply_proposer_boost<E: EthSpec>(
        &self,
        proposer_boost_root: Hash256,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> Result<bool, Error> {
        if proposer_boost_root.is_zero() {
            return Ok(false);
        }

        let block_index = *self
            .indices
            .get(&proposer_boost_root)
            .ok_or(Error::NodeUnknown(proposer_boost_root))?;
        let block = self
            .nodes
            .get(block_index)
            .ok_or(Error::InvalidNodeIndex(block_index))?;
        let parent_index = block
            .parent()
            .ok_or(Error::NodeUnknown(proposer_boost_root))?;
        let parent = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;
        let slot = block.slot();

        // Apply proposer boost if `parent` is not from the previous slot
        if parent.slot().saturating_add(1_u64) < slot {
            return Ok(true);
        }

        // Apply proposer boost if `parent` is not weak
        if !self.is_head_weak::<E>(parent, justified_balances, spec) {
            return Ok(true);
        }

        // Parent is weak. Apply boost unless there's an equivocating block at
        // the parent's slot from the same proposer.
        let parent_slot = parent.slot();
        let parent_root = parent.root();
        let parent_proposer = parent.proposer_index();

        let has_equivocation = self.nodes.iter().any(|node| {
            if let Ok(timeliness) = node.block_timeliness_ptc_threshold()
                && let Ok(proposer_index) = node.proposer_index()
            {
                timeliness
                    && Ok(proposer_index) == parent_proposer
                    && node.slot() == parent_slot
                    && node.root() != parent_root
            } else {
                // Pre-Gloas.
                false
            }
        });

        Ok(!has_equivocation)
    }

    /// Process a valid execution payload envelope for a Gloas block.
    ///
    /// Sets `payload_received` to true.
    pub fn on_valid_payload_envelope_received(&mut self, block_root: Hash256) -> Result<(), Error> {
        let index = *self
            .indices
            .get(&block_root)
            .ok_or(Error::NodeUnknown(block_root))?;
        let node = self
            .nodes
            .get_mut(index)
            .ok_or(Error::InvalidNodeIndex(index))?;
        let v29 = node
            .as_v29_mut()
            .map_err(|_| Error::InvalidNodeVariant { block_root })?;
        v29.payload_received = true;

        Ok(())
    }

    /// Updates the `block_root` and all ancestors to have validated execution payloads.
    ///
    /// Returns an error if:
    ///
    /// - The `block-root` is unknown.
    /// - Any of the to-be-validated payloads are already invalid.
    pub fn propagate_execution_payload_validation(
        &mut self,
        block_root: Hash256,
    ) -> Result<(), Error> {
        let index = *self
            .indices
            .get(&block_root)
            .ok_or(Error::NodeUnknown(block_root))?;
        self.propagate_execution_payload_validation_by_index(index)
    }

    /// Updates the `verified_node_index` and all ancestors to have validated execution payloads.
    ///
    /// This function is a no-op if called for a Gloas block.
    ///
    /// Returns an error if:
    ///
    /// - The `verified_node_index` is unknown.
    /// - Any of the to-be-validated payloads are already invalid.
    fn propagate_execution_payload_validation_by_index(
        &mut self,
        verified_node_index: usize,
    ) -> Result<(), Error> {
        let mut index = verified_node_index;
        loop {
            let node = self
                .nodes
                .get_mut(index)
                .ok_or(Error::InvalidNodeIndex(index))?;
            let parent_index = match node {
                ProtoNode::V17(node) => match node.execution_status {
                    // We have reached a node that we already know is valid. No need to iterate further
                    // since we assume an ancestors have already been set to valid.
                    ExecutionStatus::Valid(_) => return Ok(()),
                    // We have reached an irrelevant node, this node is prior to a terminal execution
                    // block. There's no need to iterate further, it's impossible for this block to have
                    // any relevant ancestors.
                    ExecutionStatus::Irrelevant(_) => return Ok(()),
                    // The block has an unknown status, set it to valid since any ancestor of a valid
                    // payload can be considered valid.
                    ExecutionStatus::Optimistic(payload_block_hash) => {
                        node.execution_status = ExecutionStatus::Valid(payload_block_hash);
                        if let Some(parent_index) = node.parent {
                            parent_index
                        } else {
                            // We have reached the root block, iteration complete.
                            return Ok(());
                        }
                    }
                    // An ancestor of the valid payload was invalid. This is a serious error which
                    // indicates a consensus failure in the execution node. This is unrecoverable.
                    ExecutionStatus::Invalid(ancestor_payload_block_hash) => {
                        return Err(Error::InvalidAncestorOfValidPayload {
                            ancestor_block_root: node.root,
                            ancestor_payload_block_hash,
                        });
                    }
                },
                // Gloas nodes should not be marked valid by this function, which exists only
                // for pre-Gloas fork choice.
                ProtoNode::V29(_) => {
                    return Ok(());
                }
            };

            index = parent_index;
        }
    }

    /// Invalidate zero or more blocks, as specified by the `InvalidationOperation`.
    ///
    /// See the documentation of `InvalidationOperation` for usage.
    // TODO(gloas): this needs some tests for the mixed Gloas/pre-Gloas case.
    pub fn propagate_execution_payload_invalidation<E: EthSpec>(
        &mut self,
        op: &InvalidationOperation,
        best_finalized_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let mut invalidated_indices: HashSet<usize> = <_>::default();
        let head_block_root = op.block_root();

        /*
         * Step 1:
         *
         * Find the `head_block_root` and maybe iterate backwards and invalidate ancestors. Record
         * all invalidated block indices in `invalidated_indices`.
         */

        let mut index = *self
            .indices
            .get(&head_block_root)
            .ok_or(Error::NodeUnknown(head_block_root))?;

        // Try to map the ancestor payload *hash* to an ancestor beacon block *root*.
        let latest_valid_ancestor_root = op
            .latest_valid_ancestor()
            .and_then(|hash| self.execution_block_hash_to_beacon_block_root(&hash));

        // Set to `true` if both conditions are satisfied:
        //
        // 1. The `head_block_root` is a descendant of `latest_valid_ancestor_hash`
        // 2. The `latest_valid_ancestor_hash` is equal to or a descendant of the finalized block.
        let latest_valid_ancestor_is_descendant =
            latest_valid_ancestor_root.is_some_and(|ancestor_root| {
                self.is_descendant(ancestor_root, head_block_root)
                    && self.is_finalized_checkpoint_or_descendant::<E>(
                        ancestor_root,
                        best_finalized_checkpoint,
                    )
            });

        // Collect all *ancestors* which were declared invalid since they reside between the
        // `head_block_root` and the `latest_valid_ancestor_root`.
        loop {
            let node = self
                .nodes
                .get_mut(index)
                .ok_or(Error::InvalidNodeIndex(index))?;

            let node_execution_status = node.execution_status();
            match node_execution_status {
                Ok(ExecutionStatus::Valid(hash))
                | Ok(ExecutionStatus::Invalid(hash))
                | Ok(ExecutionStatus::Optimistic(hash)) => {
                    // If we're no longer processing the `head_block_root` and the last valid
                    // ancestor is unknown, exit this loop and proceed to invalidate and
                    // descendants of `head_block_root`/`latest_valid_ancestor_root`.
                    //
                    // In effect, this means that if an unknown hash (junk or pre-finalization) is
                    // supplied, don't validate any ancestors. The alternative is to invalidate
                    // *all* ancestors, which would likely involve shutting down the client due to
                    // an invalid justified checkpoint.
                    if !latest_valid_ancestor_is_descendant && node.root() != head_block_root {
                        break;
                    } else if op.latest_valid_ancestor() == Some(hash) {
                        // Reached latest valid block, stop invalidating further.
                        break;
                    }
                }
                Ok(ExecutionStatus::Irrelevant(_)) => break,
                Err(_) => break,
            }

            // Only invalidate the head block if either:
            //
            // - The head block was specifically indicated to be invalidated.
            // - The latest valid hash is a known ancestor.
            if node.root() != head_block_root
                || op.invalidate_block_root()
                || latest_valid_ancestor_is_descendant
            {
                match node.execution_status() {
                    // It's illegal for an execution client to declare that some previously-valid block
                    // is now invalid. This is a consensus failure on their behalf.
                    Ok(ExecutionStatus::Valid(hash)) => {
                        return Err(Error::ValidExecutionStatusBecameInvalid {
                            block_root: node.root(),
                            payload_block_hash: hash,
                        });
                    }
                    Ok(ExecutionStatus::Optimistic(hash)) => {
                        invalidated_indices.insert(index);
                        if let ProtoNode::V17(node) = node {
                            node.execution_status = ExecutionStatus::Invalid(hash);
                        }
                    }
                    // The block is already invalid, but keep going backwards to ensure all ancestors
                    // are updated.
                    Ok(ExecutionStatus::Invalid(_)) => (),
                    // This block is pre-merge, therefore it has no execution status. Nor do its
                    // ancestors.
                    Ok(ExecutionStatus::Irrelevant(_)) => break,
                    Err(_) => break,
                }
            }

            if let Some(parent_index) = node.parent() {
                index = parent_index
            } else {
                // The root of the block tree has been reached (aka the finalized block), without
                // matching `latest_valid_ancestor_hash`. It's not possible or useful to go any
                // further back: the finalized checkpoint is invalid so all is lost!
                break;
            }
        }

        /*
         * Step 2:
         *
         * Start at either the `latest_valid_ancestor` or the `head_block_root` and iterate
         * *forwards* to invalidate all descendants of all blocks in `invalidated_indices`.
         */

        let starting_block_root = latest_valid_ancestor_root
            .filter(|_| latest_valid_ancestor_is_descendant)
            .unwrap_or(head_block_root);
        let latest_valid_ancestor_index = *self
            .indices
            .get(&starting_block_root)
            .ok_or(Error::NodeUnknown(starting_block_root))?;
        let first_potential_descendant = latest_valid_ancestor_index + 1;

        // Collect all *descendants* which have been declared invalid since they're the descendant of a block
        // with an invalid execution payload.
        for index in first_potential_descendant..self.nodes.len() {
            let node = self
                .nodes
                .get_mut(index)
                .ok_or(Error::InvalidNodeIndex(index))?;

            if let Some(parent_index) = node.parent()
                && invalidated_indices.contains(&parent_index)
            {
                match node.execution_status() {
                    Ok(ExecutionStatus::Valid(hash)) => {
                        return Err(Error::ValidExecutionStatusBecameInvalid {
                            block_root: node.root(),
                            payload_block_hash: hash,
                        });
                    }
                    Ok(ExecutionStatus::Optimistic(hash)) | Ok(ExecutionStatus::Invalid(hash)) => {
                        if let ProtoNode::V17(node) = node {
                            node.execution_status = ExecutionStatus::Invalid(hash)
                        }
                    }
                    Ok(ExecutionStatus::Irrelevant(_)) => {
                        return Err(Error::IrrelevantDescendant {
                            block_root: node.root(),
                        });
                    }
                    Err(_) => (),
                }

                invalidated_indices.insert(index);
            }
        }

        Ok(())
    }

    /// Follows the best-descendant links to find the best-block (i.e., head-block).
    ///
    /// ## Notes
    ///
    /// The result of this function is not guaranteed to be accurate if `Self::on_new_block` has
    /// been called without a subsequent `Self::apply_score_changes` call. This is because
    /// `on_new_block` does not attempt to walk backwards through the tree and update the
    /// best-child/best-descendant links.
    #[allow(clippy::too_many_arguments)]
    pub fn find_head<E: EthSpec>(
        &self,
        justified_root: &Hash256,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
        proposer_boost_root: Hash256,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> Result<(Hash256, PayloadStatus), Error> {
        let justified_index = self
            .indices
            .get(justified_root)
            .copied()
            .ok_or(Error::JustifiedNodeUnknown(*justified_root))?;

        let justified_node = self
            .nodes
            .get(justified_index)
            .ok_or(Error::InvalidJustifiedIndex(justified_index))?;

        // Since there are no valid descendants of a justified block with an invalid execution
        // payload, there would be no head to choose from.
        // Execution status tracking only exists on V17 (pre-Gloas) nodes.
        if let Ok(v17) = justified_node.as_v17()
            && v17.execution_status.is_invalid()
        {
            return Err(Error::InvalidJustifiedCheckpointExecutionStatus {
                justified_root: *justified_root,
            });
        }

        let best_fc_node = self.find_head_walk::<E>(
            justified_index,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
            proposer_boost_root,
            justified_balances,
            spec,
        )?;

        // Perform a sanity check that the node is indeed valid to be the head.
        let best_node = self
            .nodes
            .get(best_fc_node.proto_node_index)
            .ok_or(Error::InvalidNodeIndex(best_fc_node.proto_node_index))?;
        if !self.node_is_viable_for_head::<E>(
            best_node,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
        ) {
            return Err(Error::InvalidBestNode(Box::new(InvalidBestNodeInfo {
                current_slot,
                start_root: *justified_root,
                justified_checkpoint: best_justified_checkpoint,
                finalized_checkpoint: best_finalized_checkpoint,
                head_root: best_node.root(),
                head_justified_checkpoint: *best_node.justified_checkpoint(),
                head_finalized_checkpoint: *best_node.finalized_checkpoint(),
            })));
        }

        Ok((best_fc_node.root, best_fc_node.payload_status))
    }

    /// Spec: `get_filtered_block_tree`.
    ///
    /// Returns the set of node indices on viable branches — those with at least
    /// one leaf descendant with correct justified/finalized checkpoints.
    fn get_filtered_block_tree<E: EthSpec>(
        &self,
        start_index: usize,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> HashSet<usize> {
        let mut viable = HashSet::new();
        self.filter_block_tree::<E>(
            start_index,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
            &mut viable,
        );
        viable
    }

    /// Spec: `filter_block_tree`.
    fn filter_block_tree<E: EthSpec>(
        &self,
        node_index: usize,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
        viable: &mut HashSet<usize>,
    ) -> bool {
        let Some(node) = self.nodes.get(node_index) else {
            return false;
        };

        // Skip invalid children — they aren't in store.blocks in the spec.
        let children: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, child)| {
                child.parent() == Some(node_index)
                    && !child
                        .execution_status()
                        .is_ok_and(|status| status.is_invalid())
            })
            .map(|(i, _)| i)
            .collect();

        if !children.is_empty() {
            // Evaluate ALL children (no short-circuit) to mark all viable branches.
            let any_viable = children
                .iter()
                .map(|&child_index| {
                    self.filter_block_tree::<E>(
                        child_index,
                        current_slot,
                        best_justified_checkpoint,
                        best_finalized_checkpoint,
                        viable,
                    )
                })
                .collect::<Vec<_>>()
                .into_iter()
                .any(|v| v);
            if any_viable {
                viable.insert(node_index);
                return true;
            }
            return false;
        }

        // Leaf node: check viability.
        if self.node_is_viable_for_head::<E>(
            node,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
        ) {
            viable.insert(node_index);
            return true;
        }
        false
    }

    /// Spec: `get_head`.
    #[allow(clippy::too_many_arguments)]
    fn find_head_walk<E: EthSpec>(
        &self,
        start_index: usize,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
        proposer_boost_root: Hash256,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> Result<IndexedForkChoiceNode, Error> {
        let mut head = IndexedForkChoiceNode {
            root: best_justified_checkpoint.root,
            proto_node_index: start_index,
            payload_status: PayloadStatus::Pending,
        };

        // Spec: `get_filtered_block_tree`.
        let viable_nodes = self.get_filtered_block_tree::<E>(
            start_index,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
        );

        // Compute once rather than per-child per-level.
        let apply_proposer_boost =
            self.should_apply_proposer_boost::<E>(proposer_boost_root, justified_balances, spec)?;

        loop {
            let children: Vec<_> = self
                .get_node_children(&head)?
                .into_iter()
                .filter(|(fc_node, _)| viable_nodes.contains(&fc_node.proto_node_index))
                .collect();

            if children.is_empty() {
                return Ok(head);
            }

            head = children
                .into_iter()
                .map(|(child, ref proto_node)| -> Result<_, Error> {
                    let weight = self.get_weight::<E>(
                        &child,
                        proto_node,
                        apply_proposer_boost,
                        proposer_boost_root,
                        current_slot,
                        justified_balances,
                        spec,
                    )?;
                    let payload_status_tiebreaker = self.get_payload_status_tiebreaker::<E>(
                        &child,
                        proto_node,
                        current_slot,
                        proposer_boost_root,
                    )?;
                    Ok((child, weight, payload_status_tiebreaker))
                })
                .collect::<Result<Vec<_>, Error>>()?
                .into_iter()
                .max_by_key(|(child, weight, payload_status_tiebreaker)| {
                    (*weight, child.root, *payload_status_tiebreaker)
                })
                .map(|(child, _, _)| child)
                .ok_or(Error::NoViableChildren)?;
        }
    }

    /// Spec: `get_weight`.
    #[allow(clippy::too_many_arguments)]
    fn get_weight<E: EthSpec>(
        &self,
        fc_node: &IndexedForkChoiceNode,
        proto_node: &ProtoNode,
        apply_proposer_boost: bool,
        proposer_boost_root: Hash256,
        current_slot: Slot,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> Result<u64, Error> {
        if fc_node.payload_status == PayloadStatus::Pending
            || proto_node.slot().saturating_add(1_u64) != current_slot
        {
            let attestation_score = proto_node.attestation_score(fc_node.payload_status);

            if !apply_proposer_boost {
                return Ok(attestation_score);
            }

            // Spec: proposer boost is treated as a synthetic vote.
            let message = LatestMessage {
                slot: current_slot,
                root: proposer_boost_root,
                payload_present: false,
            };
            let proposer_score = if self.is_supporting_vote(fc_node, &message)? {
                get_proposer_score::<E>(justified_balances, spec)?
            } else {
                0
            };

            Ok(attestation_score.saturating_add(proposer_score))
        } else {
            Ok(0)
        }
    }

    /// Spec: `is_supporting_vote`.
    fn is_supporting_vote(
        &self,
        node: &IndexedForkChoiceNode,
        message: &LatestMessage,
    ) -> Result<bool, Error> {
        let block = self
            .nodes
            .get(node.proto_node_index)
            .ok_or(Error::InvalidNodeIndex(node.proto_node_index))?;

        if node.root == message.root {
            if node.payload_status == PayloadStatus::Pending {
                return Ok(true);
            }
            // For the proposer boost case: message.slot == current_slot == block.slot,
            // so this returns false — boost does not support EMPTY/FULL of the
            // boosted block itself, only its ancestors.
            if message.slot <= block.slot() {
                return Ok(false);
            }
            if message.payload_present {
                Ok(node.payload_status == PayloadStatus::Full)
            } else {
                Ok(node.payload_status == PayloadStatus::Empty)
            }
        } else {
            let ancestor = self.get_ancestor_node(message.root, block.slot())?;
            Ok(node.root == ancestor.root
                && (node.payload_status == PayloadStatus::Pending
                    || node.payload_status == ancestor.payload_status))
        }
    }

    /// Spec: `get_ancestor` (modified to return ForkChoiceNode with payload_status).
    fn get_ancestor_node(&self, root: Hash256, slot: Slot) -> Result<IndexedForkChoiceNode, Error> {
        let index = *self.indices.get(&root).ok_or(Error::NodeUnknown(root))?;
        let block = self
            .nodes
            .get(index)
            .ok_or(Error::InvalidNodeIndex(index))?;

        if block.slot() <= slot {
            return Ok(IndexedForkChoiceNode {
                root,
                proto_node_index: index,
                payload_status: PayloadStatus::Pending,
            });
        }

        // Walk up until we find the ancestor at `slot`.
        let mut child_index = index;
        let mut current_index = block.parent().ok_or(Error::NodeUnknown(block.root()))?;

        loop {
            let current = self
                .nodes
                .get(current_index)
                .ok_or(Error::InvalidNodeIndex(current_index))?;

            if current.slot() <= slot {
                let child = self
                    .nodes
                    .get(child_index)
                    .ok_or(Error::InvalidNodeIndex(child_index))?;
                return Ok(IndexedForkChoiceNode {
                    root: current.root(),
                    proto_node_index: current_index,
                    payload_status: child.get_parent_payload_status(),
                });
            }

            child_index = current_index;
            current_index = current.parent().ok_or(Error::NodeUnknown(current.root()))?;
        }
    }

    /// Spec: `get_node_children`.
    fn get_node_children(
        &self,
        node: &IndexedForkChoiceNode,
    ) -> Result<Vec<(IndexedForkChoiceNode, ProtoNode)>, Error> {
        if node.payload_status == PayloadStatus::Pending {
            let proto_node = self
                .nodes
                .get(node.proto_node_index)
                .ok_or(Error::InvalidNodeIndex(node.proto_node_index))?;
            let mut children = vec![(node.with_status(PayloadStatus::Empty), proto_node.clone())];
            // The FULL virtual child only exists if the payload has been received.
            if proto_node.payload_received().is_ok_and(|received| received) {
                children.push((node.with_status(PayloadStatus::Full), proto_node.clone()));
            }
            Ok(children)
        } else {
            Ok(self
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, child_node)| {
                    child_node.parent() == Some(node.proto_node_index)
                        && child_node.get_parent_payload_status() == node.payload_status
                })
                .map(|(child_index, child_node)| {
                    (
                        IndexedForkChoiceNode {
                            root: child_node.root(),
                            proto_node_index: child_index,
                            payload_status: PayloadStatus::Pending,
                        },
                        child_node.clone(),
                    )
                })
                .collect())
        }
    }

    fn get_payload_status_tiebreaker<E: EthSpec>(
        &self,
        fc_node: &IndexedForkChoiceNode,
        proto_node: &ProtoNode,
        current_slot: Slot,
        proposer_boost_root: Hash256,
    ) -> Result<u8, Error> {
        if fc_node.payload_status == PayloadStatus::Pending
            || proto_node.slot().saturating_add(1_u64) != current_slot
        {
            Ok(fc_node.payload_status as u8)
        } else if fc_node.payload_status == PayloadStatus::Empty {
            Ok(1)
        } else if self.should_extend_payload::<E>(fc_node, proto_node, proposer_boost_root)? {
            Ok(2)
        } else {
            Ok(0)
        }
    }

    fn should_extend_payload<E: EthSpec>(
        &self,
        fc_node: &IndexedForkChoiceNode,
        proto_node: &ProtoNode,
        proposer_boost_root: Hash256,
    ) -> Result<bool, Error> {
        // Per spec: `proposer_root == Root()` is one of the `or` conditions that
        // makes `should_extend_payload` return True.
        if proposer_boost_root.is_zero() {
            return Ok(true);
        }

        let proposer_boost_node_index = *self
            .indices
            .get(&proposer_boost_root)
            .ok_or(Error::NodeUnknown(proposer_boost_root))?;
        let proposer_boost_node = self
            .nodes
            .get(proposer_boost_node_index)
            .ok_or(Error::InvalidNodeIndex(proposer_boost_node_index))?;

        let parent_index = proposer_boost_node
            .parent()
            .ok_or(Error::NodeUnknown(proposer_boost_root))?;
        let proposer_boost_parent_root = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?
            .root();

        Ok(
            (proto_node.is_payload_timely::<E>() && proto_node.is_payload_data_available::<E>())
                || proposer_boost_parent_root != fc_node.root
                || proposer_boost_node.is_parent_node_full(),
        )
    }

    /// Update the tree with new finalization information. The tree is only actually pruned if both
    /// of the two following criteria are met:
    ///
    /// - The supplied finalized epoch and root are different to the current values.
    /// - The number of nodes in `self` is at least `self.prune_threshold`.
    ///
    /// # Errors
    ///
    /// Returns errors if:
    ///
    /// - The finalized epoch is less than the current one.
    /// - The finalized epoch is equal to the current one, but the finalized root is different.
    /// - There is some internal error relating to invalid indices inside `self`.
    pub fn maybe_prune(&mut self, finalized_root: Hash256) -> Result<(), Error> {
        let finalized_index = *self
            .indices
            .get(&finalized_root)
            .ok_or(Error::FinalizedNodeUnknown(finalized_root))?;

        if finalized_index < self.prune_threshold {
            // Pruning at small numbers incurs more cost than benefit.
            return Ok(());
        }

        // Remove the `self.indices` key/values for all the to-be-deleted nodes.
        for node_index in 0..finalized_index {
            let root = &self
                .nodes
                .get(node_index)
                .ok_or(Error::InvalidNodeIndex(node_index))?
                .root();
            self.indices.remove(root);
        }

        // Drop all the nodes prior to finalization.
        self.nodes = self.nodes.split_off(finalized_index);

        // Adjust the indices map.
        for (_root, index) in self.indices.iter_mut() {
            *index = index
                .checked_sub(finalized_index)
                .ok_or(Error::IndexOverflow("indices"))?;
        }

        // Iterate through all the existing nodes and adjust their indices to match the new layout
        // of `self.nodes`.
        for node in self.nodes.iter_mut() {
            if let Some(parent) = node.parent() {
                // If `node.parent` is less than `finalized_index`, set it to `None`.
                *node.parent_mut() = parent.checked_sub(finalized_index);
            }
        }

        Ok(())
    }

    /// This is the equivalent to the `filter_block_tree` function in the eth2 spec:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/fork-choice.md#filter_block_tree
    ///
    /// Any node that has a different finalized or justified epoch should not be viable for the
    /// head.
    fn node_is_viable_for_head<E: EthSpec>(
        &self,
        node: &ProtoNode,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> bool {
        if let Ok(proto_node) = node.as_v17()
            && proto_node.execution_status.is_invalid()
        {
            return false;
        }

        let genesis_epoch = Epoch::new(0);
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let node_epoch = node.slot().epoch(E::slots_per_epoch());
        let node_justified_checkpoint = node.justified_checkpoint();

        let voting_source = if current_epoch > node_epoch {
            // The block is from a prior epoch, the voting source will be pulled-up.
            node.unrealized_justified_checkpoint()
                // Sometimes we don't track the unrealized justification. In
                // that case, just use the fully-realized justified checkpoint.
                .unwrap_or(*node_justified_checkpoint)
        } else {
            // The block is not from a prior epoch, therefore the voting source
            // is not pulled up.
            *node_justified_checkpoint
        };

        let correct_justified = best_justified_checkpoint.epoch == genesis_epoch
            || voting_source.epoch == best_justified_checkpoint.epoch
            || voting_source.epoch + 2 >= current_epoch;

        let correct_finalized = best_finalized_checkpoint.epoch == genesis_epoch
            || self
                .is_finalized_checkpoint_or_descendant::<E>(node.root(), best_finalized_checkpoint);

        correct_justified && correct_finalized
    }

    /// Return a reverse iterator over the nodes which comprise the chain ending at `block_root`.
    pub fn iter_nodes<'a>(&'a self, block_root: &Hash256) -> Iter<'a> {
        let next_node_index = self.indices.get(block_root).copied();
        Iter {
            next_node_index,
            proto_array: self,
        }
    }

    /// Return a reverse iterator over the block roots of the chain ending at `block_root`.
    ///
    /// Note that unlike many other iterators, this one WILL NOT yield anything at skipped slots.
    pub fn iter_block_roots<'a>(
        &'a self,
        block_root: &Hash256,
    ) -> impl Iterator<Item = (Hash256, Slot)> + 'a {
        self.iter_nodes(block_root)
            .map(|node| (node.root(), node.slot()))
    }

    /// Returns `true` if the `descendant_root` has an ancestor with `ancestor_root`. Always
    /// returns `false` if either input root is unknown.
    ///
    /// ## Notes
    ///
    /// Still returns `true` if `ancestor_root` is known and `ancestor_root == descendant_root`.
    ///
    /// ## Warning
    ///
    /// Do not use this function to check if a block is a descendant of the
    /// finalized checkpoint. Use `Self::is_finalized_checkpoint_or_descendant`
    /// instead.
    pub fn is_descendant(&self, ancestor_root: Hash256, descendant_root: Hash256) -> bool {
        self.indices
            .get(&ancestor_root)
            .and_then(|ancestor_index| self.nodes.get(*ancestor_index))
            .and_then(|ancestor| {
                self.iter_block_roots(&descendant_root)
                    .take_while(|(_root, slot)| *slot >= ancestor.slot())
                    .find(|(_root, slot)| *slot == ancestor.slot())
                    .map(|(root, _slot)| root == ancestor_root)
            })
            .unwrap_or(false)
    }

    /// Returns `true` if `root` is equal to or a descendant of
    /// `self.finalized_checkpoint`.
    ///
    /// Notably, this function is checking ancestory of the finalized
    /// *checkpoint* not the finalized *block*.
    pub fn is_finalized_checkpoint_or_descendant<E: EthSpec>(
        &self,
        root: Hash256,
        best_finalized_checkpoint: Checkpoint,
    ) -> bool {
        let finalized_root = best_finalized_checkpoint.root;
        let finalized_slot = best_finalized_checkpoint
            .epoch
            .start_slot(E::slots_per_epoch());

        let Some(mut node) = self
            .indices
            .get(&root)
            .and_then(|index| self.nodes.get(*index))
        else {
            // An unknown root is not a finalized descendant. This line can only
            // be reached if the user supplies a root that is not known to fork
            // choice.
            return false;
        };

        // The finalized and justified checkpoints represent a list of known
        // ancestors of `node` that are likely to coincide with the store's
        // finalized checkpoint.
        //
        // Run this check once, outside of the loop rather than inside the loop.
        // If the conditions don't match for this node then they're unlikely to
        // start matching for its ancestors.
        for checkpoint in &[node.finalized_checkpoint(), node.justified_checkpoint()] {
            if **checkpoint == best_finalized_checkpoint {
                return true;
            }
        }

        for checkpoint in &[
            node.unrealized_finalized_checkpoint(),
            node.unrealized_justified_checkpoint(),
        ] {
            if checkpoint.is_some_and(|cp| cp == best_finalized_checkpoint) {
                return true;
            }
        }

        loop {
            // If `node` is less than or equal to the finalized slot then `node`
            // must be the finalized block.
            if node.slot() <= finalized_slot {
                return node.root() == finalized_root;
            }

            // Since `node` is from a higher slot that the finalized checkpoint,
            // replace `node` with the parent of `node`.
            if let Some(parent) = node.parent().and_then(|index| self.nodes.get(index)) {
                node = parent
            } else {
                // If `node` is not the finalized block and its parent does not
                // exist in fork choice, then the parent must have been pruned.
                // Proto-array only prunes blocks prior to the finalized block,
                // so this means the parent conflicts with finality.
                return false;
            };
        }
    }

    /// Returns the first *beacon block root* which contains an execution payload with the given
    /// `block_hash`, if any.
    pub fn execution_block_hash_to_beacon_block_root(
        &self,
        block_hash: &ExecutionBlockHash,
    ) -> Option<Hash256> {
        self.nodes
            .iter()
            .rev()
            .find(|node| {
                node.execution_status()
                    .ok()
                    .and_then(|execution_status| execution_status.block_hash())
                    .is_some_and(|node_block_hash| node_block_hash == *block_hash)
            })
            .map(|node| node.root())
    }

    /// Returns all nodes that have zero children and are descended from the finalized checkpoint.
    ///
    /// For informational purposes like the beacon HTTP API, we use this as the list of known heads,
    /// even though some of them might not be viable. We do this to maintain consistency between the
    /// definition of "head" used by pruning (which does not consider viability) and fork choice.
    pub fn heads_descended_from_finalization<E: EthSpec>(
        &self,
        best_finalized_checkpoint: Checkpoint,
    ) -> Vec<&ProtoNode> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(i, node)| {
                // TODO(gloas): we unoptimized this for Gloas fork choice, could re-optimize.
                let num_children = self.nodes.iter().filter(|n| n.parent() == Some(*i)).count();
                num_children == 0
                    && self.is_finalized_checkpoint_or_descendant::<E>(
                        node.root(),
                        best_finalized_checkpoint,
                    )
            })
            .map(|(_, node)| node)
            .collect()
    }
}

/// A helper method to calculate the proposer boost based on the given `justified_balances`.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/fork-choice.md#get_latest_attesting_balance
pub fn calculate_committee_fraction<E: EthSpec>(
    justified_balances: &JustifiedBalances,
    proposer_score_boost: u64,
) -> Option<u64> {
    let committee_weight = justified_balances
        .total_effective_balance
        .checked_div(E::slots_per_epoch())?;
    committee_weight
        .checked_mul(proposer_score_boost)?
        .checked_div(100)
}

/// Spec: `get_proposer_score`.
fn get_proposer_score<E: EthSpec>(
    justified_balances: &JustifiedBalances,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    let Some(proposer_score_boost) = spec.proposer_score_boost else {
        return Ok(0);
    };
    calculate_committee_fraction::<E>(justified_balances, proposer_score_boost)
        .ok_or(Error::ProposerBoostOverflow(0))
}

/// Apply a signed delta to an unsigned weight, returning an error on overflow.
fn apply_delta(weight: u64, delta: i64, index: usize) -> Result<u64, Error> {
    if delta < 0 {
        weight
            .checked_sub(delta.unsigned_abs())
            .ok_or(Error::DeltaOverflow(index))
    } else {
        weight
            .checked_add(delta as u64)
            .ok_or(Error::DeltaOverflow(index))
    }
}

/// Reverse iterator over one path through a `ProtoArray`.
pub struct Iter<'a> {
    next_node_index: Option<usize>,
    proto_array: &'a ProtoArray,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a ProtoNode;

    fn next(&mut self) -> Option<Self::Item> {
        let next_node_index = self.next_node_index?;
        let node = self.proto_array.nodes.get(next_node_index)?;
        self.next_node_index = node.parent();
        Some(node)
    }
}
