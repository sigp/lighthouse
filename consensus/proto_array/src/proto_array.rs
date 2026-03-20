use crate::error::InvalidBestNodeInfo;
use crate::{Block, ExecutionStatus, JustifiedBalances, PayloadStatus, error::Error};
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use ssz::Encode;
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
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
    #[superstruct(getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub best_child: Option<usize>,
    #[superstruct(getter(copy))]
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
    /// PTC timeliness vote bitfield, indexed by PTC committee position.
    /// Bit i set means PTC member i voted `payload_present = true`.
    /// Tiebreak derived as: `num_set_bits() > ptc_size / 2`.
    #[superstruct(only(V29))]
    pub payload_timeliness_votes: BitVector<U512>,
    /// PTC data availability vote bitfield, indexed by PTC committee position.
    /// Bit i set means PTC member i voted `blob_data_available = true`.
    /// Tiebreak derived as: `num_set_bits() > ptc_size / 2`.
    #[superstruct(only(V29))]
    pub payload_data_availability_votes: BitVector<U512>,
    /// Whether the execution payload for this block has been received and validated locally.
    /// Maps to `root in store.payload_states` in the spec.
    /// When true, `is_payload_timely` and `is_payload_data_available` return true
    /// regardless of PTC vote counts.
    #[superstruct(only(V29), partial_getter(copy))]
    pub payload_received: bool,
    /// The proposer index for this block, used by `should_apply_proposer_boost`
    /// to detect equivocations at the parent's slot.
    #[superstruct(only(V29), partial_getter(copy))]
    pub proposer_index: u64,
    /// Best child whose `parent_payload_status == Full`.
    /// Maintained alongside `best_child` to avoid O(n) scans during the V29 head walk.
    #[superstruct(only(V29), partial_getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub best_full_child: Option<usize>,
    /// Best child whose `parent_payload_status == Empty`.
    #[superstruct(only(V29), partial_getter(copy))]
    #[ssz(with = "four_byte_option_usize")]
    pub best_empty_child: Option<usize>,
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
/// This is the same notion of weight that pre-GLOAS fork choice used.
///
/// Under GLOAS we also need to track how votes contribute to the parent's virtual payload
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
}

impl NodeDelta {
    /// Classify a vote into the payload bucket it contributes to for `block_slot`.
    ///
    /// Per the GLOAS model:
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
    pub previous_proposer_boost: ProposerBoost,
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
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
        new_justified_balances: &JustifiedBalances,
        proposer_boost_root: Hash256,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if deltas.len() != self.indices.len() {
            return Err(Error::InvalidDeltaLen {
                deltas: deltas.len(),
                indices: self.indices.len(),
            });
        }

        // Default the proposer boost score to zero.
        let mut proposer_score = 0;

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

            let mut delta = if execution_status_is_invalid {
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

            // If we find the node for which the proposer boost was previously applied, decrease
            // the delta by the previous score amount.
            // TODO(gloas): implement `should_apply_proposer_boost` from the Gloas spec.
            // The spec conditionally applies proposer boost based on parent weakness and
            // early equivocations. Currently boost is applied unconditionally.
            if self.previous_proposer_boost.root != Hash256::zero()
                && self.previous_proposer_boost.root == node.root()
                // Invalid nodes will always have a weight of zero so there's no need to subtract
                // the proposer boost delta.
                && !execution_status_is_invalid
            {
                delta = delta
                    .checked_sub(self.previous_proposer_boost.score as i64)
                    .ok_or(Error::DeltaOverflow(node_index))?;
            }
            // If we find the node matching the current proposer boost root, increase
            // the delta by the new score amount (unless the block has an invalid execution status).
            // For Gloas (V29), `should_apply_proposer_boost` is checked after the loop
            // with final weights, and the boost is removed if needed.
            if let Some(proposer_score_boost) = spec.proposer_score_boost
                && proposer_boost_root != Hash256::zero()
                && proposer_boost_root == node.root()
                && !execution_status_is_invalid
            {
                proposer_score =
                    calculate_committee_fraction::<E>(new_justified_balances, proposer_score_boost)
                        .ok_or(Error::ProposerBoostOverflow(node_index))?;
                delta = delta
                    .checked_add(proposer_score as i64)
                    .ok_or(Error::DeltaOverflow(node_index))?;
            }

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
                    // V17 child of a V29 parent (fork transition): treat as FULL
                    // since V17 nodes always have execution payloads inline.
                    parent_delta.full_delta = parent_delta
                        .full_delta
                        .checked_add(delta)
                        .ok_or(Error::DeltaOverflow(parent_index))?;
                }
            }
        }

        // Gloas: now that all weights are final, check `should_apply_proposer_boost`.
        // If the boost should NOT apply, walk from the boosted node to root and subtract
        // `proposer_score` from weight and payload weights in a single pass.
        // We detect Gloas by checking the boosted node's variant (V29) directly.
        if proposer_score > 0
            && let Some(&boost_index) = self.indices.get(&proposer_boost_root)
            && self
                .nodes
                .get(boost_index)
                .is_some_and(|n| n.as_v29().is_ok())
            && !self.should_apply_proposer_boost::<E>(
                boost_index,
                proposer_score,
                new_justified_balances,
                spec,
            )?
        {
            // Single walk: subtract proposer_score from weight and payload weights.
            let mut walk_index = Some(boost_index);
            let mut child_payload_status: Option<PayloadStatus> = None;
            while let Some(idx) = walk_index {
                let node = self
                    .nodes
                    .get_mut(idx)
                    .ok_or(Error::InvalidNodeIndex(idx))?;

                *node.weight_mut() = node
                    .weight()
                    .checked_sub(proposer_score)
                    .ok_or(Error::DeltaOverflow(idx))?;

                // Subtract from the payload bucket that the child-on-path
                // contributed to (based on the child's parent_payload_status).
                if let Some(child_ps) = child_payload_status
                    && let Ok(v29) = node.as_v29_mut()
                {
                    if child_ps == PayloadStatus::Full {
                        v29.full_payload_weight = v29
                            .full_payload_weight
                            .checked_sub(proposer_score)
                            .ok_or(Error::DeltaOverflow(idx))?;
                    } else {
                        v29.empty_payload_weight = v29
                            .empty_payload_weight
                            .checked_sub(proposer_score)
                            .ok_or(Error::DeltaOverflow(idx))?;
                    }
                }

                child_payload_status = node.parent_payload_status().ok();
                walk_index = node.parent();
            }

            proposer_score = 0;
        }

        // After applying all deltas, update the `previous_proposer_boost`.
        self.previous_proposer_boost = ProposerBoost {
            root: proposer_boost_root,
            score: proposer_score,
        };

        // A second time, iterate backwards through all indices in `self.nodes`.
        //
        // We _must_ perform these functions separate from the weight-updating loop above to ensure
        // that we have a fully coherent set of weights before updating parent
        // best-child/descendant.
        for node_index in (0..self.nodes.len()).rev() {
            let node = self
                .nodes
                .get_mut(node_index)
                .ok_or(Error::InvalidNodeIndex(node_index))?;

            // If the node has a parent, try to update its best-child and best-descendant.
            if let Some(parent_index) = node.parent() {
                self.maybe_update_best_child_and_descendant::<E>(
                    parent_index,
                    node_index,
                    current_slot,
                    best_justified_checkpoint,
                    best_finalized_checkpoint,
                )?;
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
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        // If the block is already known, simply ignore it.
        if self.indices.contains_key(&block.root) {
            return Ok(());
        }

        let node_index = self.nodes.len();

        let parent_index = block
            .parent_root
            .and_then(|parent| self.indices.get(&parent).copied());

        let node = if !spec.fork_name_at_slot::<E>(current_slot).gloas_enabled() {
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

            let parent_payload_status: PayloadStatus = if let Some(parent_node) =
                parent_index.and_then(|idx| self.nodes.get(idx))
            {
                // Get the parent's execution block hash, handling both V17 and V29 nodes.
                // V17 parents occur during the Gloas fork transition.
                // TODO(gloas): the spec's `get_parent_payload_status` assumes all blocks are
                // post-Gloas with bids. Revisit once the spec clarifies fork-transition behavior.
                let parent_el_block_hash = match parent_node {
                    ProtoNode::V29(v29) => Some(v29.execution_payload_block_hash),
                    ProtoNode::V17(v17) => v17.execution_status.block_hash(),
                };
                // Per spec's `is_parent_node_full`: if the child's EL parent hash
                // matches the parent's EL block hash, the child extends the parent's
                // payload chain, meaning the parent was Full.
                if parent_el_block_hash.is_some_and(|hash| execution_payload_parent_hash == hash) {
                    PayloadStatus::Full
                } else {
                    PayloadStatus::Empty
                }
            } else {
                // Parent is missing (genesis or pruned due to finalization). Default to Full
                // since this path should only be hit at Gloas genesis, and extending the payload
                // chain is the safe default.
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
                best_child: None,
                best_descendant: None,
                unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
                unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint,
                parent_payload_status,
                empty_payload_weight: 0,
                full_payload_weight: 0,
                execution_payload_block_hash,
                // Per spec `get_forkchoice_store`: the anchor block's PTC votes are
                // initialized to all-True, ensuring `is_payload_timely` and
                // `is_payload_data_available` return true for the anchor.
                payload_timeliness_votes: if is_genesis {
                    let mut bv = BitVector::new();
                    for i in 0..bv.len() {
                        let _ = bv.set(i, true);
                    }
                    bv
                } else {
                    BitVector::default()
                },
                payload_data_availability_votes: if is_genesis {
                    let mut bv = BitVector::new();
                    for i in 0..bv.len() {
                        let _ = bv.set(i, true);
                    }
                    bv
                } else {
                    BitVector::default()
                },
                payload_received: is_genesis,
                proposer_index: block.proposer_index.unwrap_or(0),
                best_full_child: None,
                best_empty_child: None,
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

        if let Some(parent_index) = node.parent() {
            self.maybe_update_best_child_and_descendant::<E>(
                parent_index,
                node_index,
                current_slot,
                best_justified_checkpoint,
                best_finalized_checkpoint,
            )?;

            if matches!(block.execution_status, ExecutionStatus::Valid(_)) {
                self.propagate_execution_payload_validation_by_index(parent_index)?;
            }
        }

        Ok(())
    }

    /// Spec's `should_apply_proposer_boost` for Gloas.
    ///
    /// Returns `true` if the proposer boost should be kept. Returns `false` if the
    /// boost should be subtracted (invalidated) because the parent is weak and there
    /// are no equivocating blocks at the parent's slot.
    fn should_apply_proposer_boost<E: EthSpec>(
        &self,
        boost_index: usize,
        proposer_score: u64,
        justified_balances: &JustifiedBalances,
        spec: &ChainSpec,
    ) -> Result<bool, Error> {
        let boost_node = self
            .nodes
            .get(boost_index)
            .ok_or(Error::InvalidNodeIndex(boost_index))?;

        let Some(parent_index) = boost_node.parent() else {
            return Ok(true); // Genesis — always apply.
        };

        let parent = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;

        // Parent not from the immediately previous slot — always apply.
        if parent.slot() + 1 < boost_node.slot() {
            return Ok(true);
        }

        // Check if the parent is "weak" (low attestation weight).
        // Parent weight currently includes the back-propagated boost, so subtract it.
        let reorg_threshold = calculate_committee_fraction::<E>(
            justified_balances,
            spec.reorg_head_weight_threshold.unwrap_or(20),
        )
        .unwrap_or(0);

        let parent_weight_without_boost = parent.weight().saturating_sub(proposer_score);
        if parent_weight_without_boost >= reorg_threshold {
            return Ok(true); // Parent is not weak — apply.
        }

        // Parent is weak. Apply boost unless there's an equivocating block at
        // the parent's slot from the same proposer.
        let parent_slot = parent.slot();
        let parent_root = parent.root();
        let parent_proposer = parent.proposer_index().unwrap_or(u64::MAX);

        let has_equivocation = self.nodes.iter().any(|n| {
            n.as_v29().is_ok()
                && n.slot() == parent_slot
                && n.root() != parent_root
                && n.proposer_index().unwrap_or(u64::MAX - 1) == parent_proposer
        });

        Ok(!has_equivocation)
    }

    /// Process an execution payload for a Gloas block.
    ///
    /// Sets `payload_received` to true, which makes `is_payload_timely` and
    /// `is_payload_data_available` return true regardless of PTC votes.
    /// This maps to `store.payload_states[root] = state` in the spec.
    pub fn on_valid_execution_payload(&mut self, block_root: Hash256) -> Result<(), Error> {
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
                // Gloas nodes don't carry `ExecutionStatus`. Mark the validated
                // block as payload-received so that `is_payload_timely` /
                // `is_payload_data_available` and `index == 1` attestations work.
                ProtoNode::V29(node) => {
                    if index == verified_node_index {
                        node.payload_received = true;
                    }
                    if let Some(parent_index) = node.parent {
                        parent_index
                    } else {
                        return Ok(());
                    }
                }
            };

            index = parent_index;
        }
    }

    /// Invalidate zero or more blocks, as specified by the `InvalidationOperation`.
    ///
    /// See the documentation of `InvalidationOperation` for usage.
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
                        // If the `best_child` or `best_descendant` of the latest valid hash was
                        // invalidated, set those fields to `None`.
                        //
                        // In theory, an invalid `best_child` necessarily infers an invalid
                        // `best_descendant`. However, we check each variable independently to
                        // defend against errors which might result in an invalid block being set as
                        // head.
                        if node
                            .best_child()
                            .is_some_and(|i| invalidated_indices.contains(&i))
                        {
                            *node.best_child_mut() = None
                        }
                        if node
                            .best_descendant()
                            .is_some_and(|i| invalidated_indices.contains(&i))
                        {
                            *node.best_descendant_mut() = None
                        }

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

                        // It's impossible for an invalid block to lead to a "best" block, so set these
                        // fields to `None`.
                        //
                        // Failing to set these values will result in `Self::node_leads_to_viable_head`
                        // returning `false` for *valid* ancestors of invalid blocks.
                        *node.best_child_mut() = None;
                        *node.best_descendant_mut() = None;
                    }
                    // The block is already invalid, but keep going backwards to ensure all ancestors
                    // are updated.
                    Ok(ExecutionStatus::Invalid(_)) => (),
                    // This block is pre-merge, therefore it has no execution status. Nor do its
                    // ancestors.
                    Ok(ExecutionStatus::Irrelevant(_)) => break,
                    Err(_) => (),
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
    pub fn find_head<E: EthSpec>(
        &self,
        justified_root: &Hash256,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> Result<Hash256, Error> {
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

        // For V29 (Gloas) justified nodes, use the virtual tree walk directly.
        if justified_node.as_v29().is_ok() {
            return self.find_head_v29_walk::<E>(justified_index, current_slot);
        }

        // Pre-Gloas justified node, but descendants may be V29.
        // Walk via best_child chain; switch to V29 walk when we hit one.
        if justified_node.best_child().is_some() || justified_node.best_descendant().is_some() {
            let mut current_index = justified_index;
            loop {
                let node = self
                    .nodes
                    .get(current_index)
                    .ok_or(Error::InvalidNodeIndex(current_index))?;

                // Hit a V29 node — switch to virtual tree walk.
                if node.as_v29().is_ok() {
                    return self.find_head_v29_walk::<E>(current_index, current_slot);
                }

                // V17 node: follow best_child.
                if let Some(bc_idx) = node.best_child() {
                    current_index = bc_idx;
                } else {
                    break;
                }
            }

            let head_node = self
                .nodes
                .get(current_index)
                .ok_or(Error::InvalidNodeIndex(current_index))?;
            return Ok(head_node.root());
        }

        // Pre-Gloas fallback: use best_descendant directly.
        let best_descendant_index = justified_node.best_descendant().unwrap_or(justified_index);

        let best_node = self
            .nodes
            .get(best_descendant_index)
            .ok_or(Error::InvalidBestDescendant(best_descendant_index))?;

        // Perform a sanity check that the node is indeed valid to be the head.
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

        Ok(best_node.root())
    }

    /// V29 virtual tree walk for `find_head`.
    ///
    /// At each V29 node, determine the preferred payload direction (FULL or EMPTY)
    /// by comparing weights, then follow the direction-specific best_child pointer.
    /// O(depth) — no scanning.
    fn find_head_v29_walk<E: EthSpec>(
        &self,
        start_index: usize,
        current_slot: Slot,
    ) -> Result<Hash256, Error> {
        let ptc_size = E::ptc_size();
        let mut current_index = start_index;

        loop {
            let node = self
                .nodes
                .get(current_index)
                .ok_or(Error::InvalidNodeIndex(current_index))?;

            let Ok(v29) = node.as_v29() else { break };

            let prefer_full = Self::v29_prefer_full(v29, node.slot(), current_slot, ptc_size);

            // O(1) lookup via direction-specific best_child pointers.
            let next = if prefer_full {
                v29.best_full_child
            } else {
                v29.best_empty_child
            };

            if let Some(child_index) = next {
                current_index = child_index;
            } else {
                break;
            }
        }

        let head_node = self
            .nodes
            .get(current_index)
            .ok_or(Error::InvalidNodeIndex(current_index))?;
        Ok(head_node.root())
    }

    /// Determine whether a V29 node prefers the FULL or EMPTY direction.
    fn v29_prefer_full(
        v29: &ProtoNodeV29,
        node_slot: Slot,
        current_slot: Slot,
        ptc_size: usize,
    ) -> bool {
        if !v29.payload_received {
            return false;
        }
        if node_slot + 1 != current_slot {
            // Weight comparison, tiebreak to payload_received.
            if v29.full_payload_weight != v29.empty_payload_weight {
                v29.full_payload_weight > v29.empty_payload_weight
            } else {
                v29.payload_received
            }
        } else {
            // Previous slot: PTC tiebreaker only.
            is_payload_timely(
                &v29.payload_timeliness_votes,
                ptc_size,
                v29.payload_received,
            ) && is_payload_data_available(
                &v29.payload_data_availability_votes,
                ptc_size,
                v29.payload_received,
            )
        }
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
            if let Some(best_child) = node.best_child() {
                *node.best_child_mut() = Some(
                    best_child
                        .checked_sub(finalized_index)
                        .ok_or(Error::IndexOverflow("best_child"))?,
                );
            }
            if let Some(best_descendant) = node.best_descendant() {
                *node.best_descendant_mut() = Some(
                    best_descendant
                        .checked_sub(finalized_index)
                        .ok_or(Error::IndexOverflow("best_descendant"))?,
                );
            }
            if let Ok(v29) = node.as_v29_mut() {
                if let Some(idx) = v29.best_full_child {
                    v29.best_full_child = Some(
                        idx.checked_sub(finalized_index)
                            .ok_or(Error::IndexOverflow("best_full_child"))?,
                    );
                }
                if let Some(idx) = v29.best_empty_child {
                    v29.best_empty_child = Some(
                        idx.checked_sub(finalized_index)
                            .ok_or(Error::IndexOverflow("best_empty_child"))?,
                    );
                }
            }
        }

        Ok(())
    }

    /// Observe the parent at `parent_index` with respect to the child at `child_index` and
    /// potentially modify the `parent.best_child` and `parent.best_descendant` values.
    ///
    /// ## Detail
    ///
    /// There are four outcomes:
    ///
    /// - The child is already the best child but it's now invalid due to a FFG change and should be removed.
    /// - The child is already the best child and the parent is updated with the new
    ///   best-descendant.
    /// - The child is not the best child but becomes the best child.
    /// - The child is not the best child and does not become the best child.
    fn maybe_update_best_child_and_descendant<E: EthSpec>(
        &mut self,
        parent_index: usize,
        child_index: usize,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let child = self
            .nodes
            .get(child_index)
            .ok_or(Error::InvalidNodeIndex(child_index))?;

        let parent = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;

        let child_leads_to_viable_head = self.node_leads_to_viable_head::<E>(
            child,
            current_slot,
            best_justified_checkpoint,
            best_finalized_checkpoint,
        )?;

        // Per spec `should_extend_payload`: if the proposer-boosted block is a child of
        // this parent and extends Empty, force Empty preference regardless of
        // weights/tiebreaker.
        let proposer_boost_root = self.previous_proposer_boost.root;
        let proposer_boost = !proposer_boost_root.is_zero()
            && self
                .indices
                .get(&proposer_boost_root)
                .and_then(|&idx| self.nodes.get(idx))
                .is_some_and(|boost_node| {
                    boost_node.parent() == Some(parent_index)
                        && boost_node
                            .parent_payload_status()
                            .is_ok_and(|s| s != PayloadStatus::Full)
                });

        // These three variables are aliases to the three options that we may set the
        // `parent.best_child` and `parent.best_descendant` to.
        //
        // I use the aliases to assist readability.
        let change_to_none = (None, None);
        let change_to_child = (
            Some(child_index),
            child.best_descendant().or(Some(child_index)),
        );
        let no_change = (parent.best_child(), parent.best_descendant());

        // For V29 (GLOAS) parents, the spec's virtual tree model determines a preferred
        // FULL or EMPTY direction at each node. Weight is the primary selector among
        // viable children; direction matching is the tiebreaker when weights are equal.
        let child_matches_dir = child_matches_parent_payload_preference(
            parent,
            child,
            current_slot,
            E::ptc_size(),
            proposer_boost,
        );

        let (new_best_child, new_best_descendant) =
            if let Some(best_child_index) = parent.best_child() {
                if best_child_index == child_index && !child_leads_to_viable_head {
                    // If the child is already the best-child of the parent but it's not viable for
                    // the head, remove it.
                    change_to_none
                } else if best_child_index == child_index {
                    // If the child is the best-child already, set it again to ensure that the
                    // best-descendant of the parent is updated.
                    change_to_child
                } else {
                    let best_child = self
                        .nodes
                        .get(best_child_index)
                        .ok_or(Error::InvalidBestDescendant(best_child_index))?;

                    let best_child_leads_to_viable_head = self.node_leads_to_viable_head::<E>(
                        best_child,
                        current_slot,
                        best_justified_checkpoint,
                        best_finalized_checkpoint,
                    )?;

                    let best_child_matches_dir = child_matches_parent_payload_preference(
                        parent,
                        best_child,
                        current_slot,
                        E::ptc_size(),
                        proposer_boost,
                    );

                    if child_leads_to_viable_head && !best_child_leads_to_viable_head {
                        // The child leads to a viable head, but the current best-child doesn't.
                        change_to_child
                    } else if !child_leads_to_viable_head && best_child_leads_to_viable_head {
                        // The best child leads to a viable head, but the child doesn't.
                        no_change
                    } else if child.weight() > best_child.weight() {
                        // Weight is the primary selector after viability.
                        change_to_child
                    } else if child.weight() < best_child.weight() {
                        no_change
                    } else if child_matches_dir && !best_child_matches_dir {
                        // Equal weight: direction matching is the tiebreaker.
                        change_to_child
                    } else if !child_matches_dir && best_child_matches_dir {
                        no_change
                    } else if *child.root() >= *best_child.root() {
                        // Final tie-breaker: break by root hash.
                        change_to_child
                    } else {
                        no_change
                    }
                }
            } else if child_leads_to_viable_head {
                // No current best-child: set if child is viable.
                change_to_child
            } else {
                // Child is not viable.
                no_change
            };

        // Capture child info before mutable borrows.
        let child = self
            .nodes
            .get(child_index)
            .ok_or(Error::InvalidNodeIndex(child_index))?;
        let child_payload_dir = child.parent_payload_status().ok();
        let child_weight = child.weight();
        let child_root = child.root();

        // Update general best_child/best_descendant.
        let parent = self
            .nodes
            .get_mut(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;

        *parent.best_child_mut() = new_best_child;
        *parent.best_descendant_mut() = new_best_descendant;

        // For V29 parents: also maintain direction-specific best_child pointers
        // so the V29 head walk can pick the right child in O(1).
        if parent.as_v29().is_ok()
            && let Some(dir) = child_payload_dir
        {
            self.update_directional_best_child::<E>(
                parent_index,
                child_index,
                dir,
                child_leads_to_viable_head,
                child_weight,
                child_root,
                current_slot,
                best_justified_checkpoint,
                best_finalized_checkpoint,
            )?;
        }

        Ok(())
    }

    /// Update `best_full_child` or `best_empty_child` on a V29 parent.
    #[allow(clippy::too_many_arguments)]
    fn update_directional_best_child<E: EthSpec>(
        &mut self,
        parent_index: usize,
        child_index: usize,
        dir: PayloadStatus,
        child_viable: bool,
        child_weight: u64,
        child_root: Hash256,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        let parent_v29 = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?
            .as_v29()
            .map_err(|_| Error::InvalidNodeIndex(parent_index))?;

        let current_best = match dir {
            PayloadStatus::Full => parent_v29.best_full_child,
            PayloadStatus::Empty => parent_v29.best_empty_child,
            PayloadStatus::Pending => return Ok(()),
        };

        if !child_viable {
            // Remove if this child was the directional best but is no longer viable.
            if current_best == Some(child_index) {
                let parent_v29 = self
                    .nodes
                    .get_mut(parent_index)
                    .ok_or(Error::InvalidNodeIndex(parent_index))?
                    .as_v29_mut()
                    .map_err(|_| Error::InvalidNodeIndex(parent_index))?;
                match dir {
                    PayloadStatus::Full => parent_v29.best_full_child = None,
                    PayloadStatus::Empty => parent_v29.best_empty_child = None,
                    PayloadStatus::Pending => {}
                }
            }
            return Ok(());
        }

        let replace = match current_best {
            None => true,
            Some(best_idx) => {
                let best_node = self
                    .nodes
                    .get(best_idx)
                    .ok_or(Error::InvalidNodeIndex(best_idx))?;
                let best_viable = self.node_leads_to_viable_head::<E>(
                    best_node,
                    current_slot,
                    best_justified_checkpoint,
                    best_finalized_checkpoint,
                )?;
                if !best_viable {
                    true
                } else if child_weight != best_node.weight() {
                    child_weight > best_node.weight()
                } else {
                    *child_root >= *best_node.root()
                }
            }
        };

        if replace {
            let parent_v29 = self
                .nodes
                .get_mut(parent_index)
                .ok_or(Error::InvalidNodeIndex(parent_index))?
                .as_v29_mut()
                .map_err(|_| Error::InvalidNodeIndex(parent_index))?;
            match dir {
                PayloadStatus::Full => parent_v29.best_full_child = Some(child_index),
                PayloadStatus::Empty => parent_v29.best_empty_child = Some(child_index),
                PayloadStatus::Pending => {}
            }
        }

        Ok(())
    }

    /// Indicates if the node itself is viable for the head, or if its best descendant is viable
    /// for the head.
    fn node_leads_to_viable_head<E: EthSpec>(
        &self,
        node: &ProtoNode,
        current_slot: Slot,
        best_justified_checkpoint: Checkpoint,
        best_finalized_checkpoint: Checkpoint,
    ) -> Result<bool, Error> {
        let best_descendant_is_viable_for_head =
            if let Some(best_descendant_index) = node.best_descendant() {
                let best_descendant = self
                    .nodes
                    .get(best_descendant_index)
                    .ok_or(Error::InvalidBestDescendant(best_descendant_index))?;

                self.node_is_viable_for_head::<E>(
                    best_descendant,
                    current_slot,
                    best_justified_checkpoint,
                    best_finalized_checkpoint,
                )
            } else {
                false
            };

        Ok(best_descendant_is_viable_for_head
            || self.node_is_viable_for_head::<E>(
                node,
                current_slot,
                best_justified_checkpoint,
                best_finalized_checkpoint,
            ))
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
            .filter(|node| {
                node.best_child().is_none()
                    && self.is_finalized_checkpoint_or_descendant::<E>(
                        node.root(),
                        best_finalized_checkpoint,
                    )
            })
            .collect()
    }
}

/// For V29 parents, returns `true` if the child's `parent_payload_status` matches the parent's
/// preferred payload status per spec `should_extend_payload`.
///
/// If `proposer_boost` is set, the parent unconditionally prefers Empty (the proposer-boosted
/// block is a child of this parent and extends Empty). Otherwise, when full and empty weights
/// are unequal the higher weight wins; when equal, the tiebreaker uses PTC votes.
///
/// For V17 parents (or mixed), always returns `true` (no payload preference).
fn child_matches_parent_payload_preference(
    parent: &ProtoNode,
    child: &ProtoNode,
    current_slot: Slot,
    ptc_size: usize,
    proposer_boost: bool,
) -> bool {
    let (Ok(parent_v29), Ok(child_v29)) = (parent.as_v29(), child.as_v29()) else {
        return true;
    };

    // Per spec `should_extend_payload`: if the proposer-boosted block extends Empty from
    // this parent, unconditionally prefer Empty.
    if proposer_boost {
        return child_v29.parent_payload_status == PayloadStatus::Empty;
    }

    // Per spec `get_weight`: FULL/EMPTY virtual nodes at `current_slot - 1` have weight 0.
    // The PTC is still voting, so payload preference is determined solely by the tiebreaker.
    let use_tiebreaker_only = parent.slot() + 1 == current_slot;
    let prefers_full = if !use_tiebreaker_only
        && parent_v29.full_payload_weight > parent_v29.empty_payload_weight
    {
        true
    } else if !use_tiebreaker_only
        && parent_v29.empty_payload_weight > parent_v29.full_payload_weight
    {
        false
    } else if use_tiebreaker_only {
        // Previous slot: should_extend_payload = is_payload_timely && is_payload_data_available.
        is_payload_timely(
            &parent_v29.payload_timeliness_votes,
            ptc_size,
            parent_v29.payload_received,
        ) && is_payload_data_available(
            &parent_v29.payload_data_availability_votes,
            ptc_size,
            parent_v29.payload_received,
        )
    } else {
        // Not previous slot: should_extend_payload = true.
        // Full wins the tiebreaker (1 > 0) when the payload has been received.
        parent_v29.payload_received
    };
    if prefers_full {
        child_v29.parent_payload_status == PayloadStatus::Full
    } else {
        child_v29.parent_payload_status == PayloadStatus::Empty
    }
}

/// Derive `is_payload_timely` from the timeliness vote bitfield.
///
/// Per spec: returns false if the payload has not been received locally
/// (`payload_received == false`, i.e. `root not in store.payload_states`),
/// regardless of PTC votes. Both local receipt and PTC threshold are required.
pub fn is_payload_timely(
    timeliness_votes: &BitVector<U512>,
    ptc_size: usize,
    payload_received: bool,
) -> bool {
    payload_received && timeliness_votes.num_set_bits() > ptc_size / 2
}

/// Derive `is_payload_data_available` from the data availability vote bitfield.
///
/// Per spec: returns false if the payload has not been received locally
/// (`payload_received == false`, i.e. `root not in store.payload_states`),
/// regardless of PTC votes. Both local receipt and PTC threshold are required.
pub fn is_payload_data_available(
    availability_votes: &BitVector<U512>,
    ptc_size: usize,
    payload_received: bool,
) -> bool {
    payload_received && availability_votes.num_set_bits() > ptc_size / 2
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
