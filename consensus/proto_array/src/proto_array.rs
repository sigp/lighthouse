use crate::error::InvalidBestNodeInfo;
use crate::{error::Error, Block, ExecutionStatus};
use serde_derive::{Deserialize, Serialize};
use ssz::four_byte_option_impl;
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
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

#[derive(Clone, PartialEq, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct ProtoNode {
    /// The `slot` is not necessary for `ProtoArray`, it just exists so external components can
    /// easily query the block slot. This is useful for upstream fork choice logic.
    pub slot: Slot,
    /// The `state_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely attestation verification).
    pub state_root: Hash256,
    /// The root that would be used for the `attestation.data.target.root` if a LMD vote was cast
    /// for this block.
    ///
    /// The `target_root` is not necessary for `ProtoArray` either, it also just exists for upstream
    /// components (namely fork choice attestation verification).
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub root: Hash256,
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub finalized_checkpoint: Option<Checkpoint>,
    pub weight: u64,
    #[ssz(with = "four_byte_option_usize")]
    pub best_child: Option<usize>,
    #[ssz(with = "four_byte_option_usize")]
    pub best_descendant: Option<usize>,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash.
    pub execution_status: ExecutionStatus,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
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

/// Indicate whether we should strictly count unrealized justification/finalization votes.
#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum CountUnrealizedFull {
    True,
    #[default]
    False,
}

impl From<bool> for CountUnrealizedFull {
    fn from(b: bool) -> Self {
        if b {
            CountUnrealizedFull::True
        } else {
            CountUnrealizedFull::False
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ProtoArray {
    /// Do not attempt to prune the tree unless it has at least this many nodes. Small prunes
    /// simply waste time.
    pub prune_threshold: usize,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub nodes: Vec<ProtoNode>,
    pub indices: HashMap<Hash256, usize>,
    pub previous_proposer_boost: ProposerBoost,
    pub count_unrealized_full: CountUnrealizedFull,
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
    /// should become the best child.
    /// - If required, update the parents best-descendant with the current node or its best-descendant.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_score_changes<E: EthSpec>(
        &mut self,
        mut deltas: Vec<i64>,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        new_balances: &[u64],
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

        if justified_checkpoint != self.justified_checkpoint
            || finalized_checkpoint != self.finalized_checkpoint
        {
            self.justified_checkpoint = justified_checkpoint;
            self.finalized_checkpoint = finalized_checkpoint;
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
            if node.root == Hash256::zero() {
                continue;
            }

            let execution_status_is_invalid = node.execution_status.is_invalid();

            let mut node_delta = if execution_status_is_invalid {
                // If the node has an invalid execution payload, reduce its weight to zero.
                0_i64
                    .checked_sub(node.weight as i64)
                    .ok_or(Error::InvalidExecutionDeltaOverflow(node_index))?
            } else {
                deltas
                    .get(node_index)
                    .copied()
                    .ok_or(Error::InvalidNodeDelta(node_index))?
            };

            // If we find the node for which the proposer boost was previously applied, decrease
            // the delta by the previous score amount.
            if self.previous_proposer_boost.root != Hash256::zero()
                && self.previous_proposer_boost.root == node.root
                // Invalid nodes will always have a weight of zero so there's no need to subtract
                // the proposer boost delta.
                && !execution_status_is_invalid
            {
                node_delta = node_delta
                    .checked_sub(self.previous_proposer_boost.score as i64)
                    .ok_or(Error::DeltaOverflow(node_index))?;
            }
            // If we find the node matching the current proposer boost root, increase
            // the delta by the new score amount (unless the block has an invalid execution status).
            //
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/fork-choice.md#get_latest_attesting_balance
            if let Some(proposer_score_boost) = spec.proposer_score_boost {
                if proposer_boost_root != Hash256::zero()
                    && proposer_boost_root == node.root
                    // Invalid nodes (or their ancestors) should not receive a proposer boost.
                    && !execution_status_is_invalid
                {
                    proposer_score =
                        calculate_proposer_boost::<E>(new_balances, proposer_score_boost)
                            .ok_or(Error::ProposerBoostOverflow(node_index))?;
                    node_delta = node_delta
                        .checked_add(proposer_score as i64)
                        .ok_or(Error::DeltaOverflow(node_index))?;
                }
            }

            // Apply the delta to the node.
            if execution_status_is_invalid {
                // Invalid nodes always have a weight of 0.
                node.weight = 0
            } else if node_delta < 0 {
                // Note: I am conflicted about whether to use `saturating_sub` or `checked_sub`
                // here.
                //
                // I can't think of any valid reason why `node_delta.abs()` should be greater than
                // `node.weight`, so I have chosen `checked_sub` to try and fail-fast if there is
                // some error.
                //
                // However, I am not fully convinced that some valid case for `saturating_sub` does
                // not exist.
                node.weight = node
                    .weight
                    .checked_sub(node_delta.unsigned_abs())
                    .ok_or(Error::DeltaOverflow(node_index))?;
            } else {
                node.weight = node
                    .weight
                    .checked_add(node_delta as u64)
                    .ok_or(Error::DeltaOverflow(node_index))?;
            }

            // Update the parent delta (if any).
            if let Some(parent_index) = node.parent {
                let parent_delta = deltas
                    .get_mut(parent_index)
                    .ok_or(Error::InvalidParentDelta(parent_index))?;

                // Back-propagate the nodes delta to its parent.
                *parent_delta += node_delta;
            }
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
            if let Some(parent_index) = node.parent {
                self.maybe_update_best_child_and_descendant::<E>(
                    parent_index,
                    node_index,
                    current_slot,
                )?;
            }
        }

        Ok(())
    }

    /// Register a block with the fork choice.
    ///
    /// It is only sane to supply a `None` parent for the genesis block.
    pub fn on_block<E: EthSpec>(&mut self, block: Block, current_slot: Slot) -> Result<(), Error> {
        // If the block is already known, simply ignore it.
        if self.indices.contains_key(&block.root) {
            return Ok(());
        }

        let node_index = self.nodes.len();

        let node = ProtoNode {
            slot: block.slot,
            root: block.root,
            target_root: block.target_root,
            current_epoch_shuffling_id: block.current_epoch_shuffling_id,
            next_epoch_shuffling_id: block.next_epoch_shuffling_id,
            state_root: block.state_root,
            parent: block
                .parent_root
                .and_then(|parent| self.indices.get(&parent).copied()),
            justified_checkpoint: Some(block.justified_checkpoint),
            finalized_checkpoint: Some(block.finalized_checkpoint),
            weight: 0,
            best_child: None,
            best_descendant: None,
            execution_status: block.execution_status,
            unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint,
        };

        // If the parent has an invalid execution status, return an error before adding the block to
        // `self`.
        if let Some(parent_index) = node.parent {
            let parent = self
                .nodes
                .get(parent_index)
                .ok_or(Error::InvalidNodeIndex(parent_index))?;
            if parent.execution_status.is_invalid() {
                return Err(Error::ParentExecutionStatusIsInvalid {
                    block_root: block.root,
                    parent_root: parent.root,
                });
            }
        }

        self.indices.insert(node.root, node_index);
        self.nodes.push(node.clone());

        if let Some(parent_index) = node.parent {
            self.maybe_update_best_child_and_descendant::<E>(
                parent_index,
                node_index,
                current_slot,
            )?;

            if matches!(block.execution_status, ExecutionStatus::Valid(_)) {
                self.propagate_execution_payload_validation_by_index(parent_index)?;
            }
        }

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
            let parent_index = match node.execution_status {
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
                    })
                }
            };

            index = parent_index;
        }
    }

    /// Invalidate zero or more blocks, as specified by the `InvalidationOperation`.
    ///
    /// See the documentation of `InvalidationOperation` for usage.
    pub fn propagate_execution_payload_invalidation(
        &mut self,
        op: &InvalidationOperation,
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
            latest_valid_ancestor_root.map_or(false, |ancestor_root| {
                self.is_descendant(ancestor_root, head_block_root)
                    && self.is_descendant(self.finalized_checkpoint.root, ancestor_root)
            });

        // Collect all *ancestors* which were declared invalid since they reside between the
        // `head_block_root` and the `latest_valid_ancestor_root`.
        loop {
            let node = self
                .nodes
                .get_mut(index)
                .ok_or(Error::InvalidNodeIndex(index))?;

            match node.execution_status {
                ExecutionStatus::Valid(hash)
                | ExecutionStatus::Invalid(hash)
                | ExecutionStatus::Optimistic(hash) => {
                    // If we're no longer processing the `head_block_root` and the last valid
                    // ancestor is unknown, exit this loop and proceed to invalidate and
                    // descendants of `head_block_root`/`latest_valid_ancestor_root`.
                    //
                    // In effect, this means that if an unknown hash (junk or pre-finalization) is
                    // supplied, don't validate any ancestors. The alternative is to invalidate
                    // *all* ancestors, which would likely involve shutting down the client due to
                    // an invalid justified checkpoint.
                    if !latest_valid_ancestor_is_descendant && node.root != head_block_root {
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
                            .best_child
                            .map_or(false, |i| invalidated_indices.contains(&i))
                        {
                            node.best_child = None
                        }
                        if node
                            .best_descendant
                            .map_or(false, |i| invalidated_indices.contains(&i))
                        {
                            node.best_descendant = None
                        }

                        break;
                    }
                }
                ExecutionStatus::Irrelevant(_) => break,
            }

            // Only invalidate the head block if either:
            //
            // - The head block was specifically indicated to be invalidated.
            // - The latest valid hash is a known ancestor.
            if node.root != head_block_root
                || op.invalidate_block_root()
                || latest_valid_ancestor_is_descendant
            {
                match &node.execution_status {
                    // It's illegal for an execution client to declare that some previously-valid block
                    // is now invalid. This is a consensus failure on their behalf.
                    ExecutionStatus::Valid(hash) => {
                        return Err(Error::ValidExecutionStatusBecameInvalid {
                            block_root: node.root,
                            payload_block_hash: *hash,
                        })
                    }
                    ExecutionStatus::Optimistic(hash) => {
                        invalidated_indices.insert(index);
                        node.execution_status = ExecutionStatus::Invalid(*hash);

                        // It's impossible for an invalid block to lead to a "best" block, so set these
                        // fields to `None`.
                        //
                        // Failing to set these values will result in `Self::node_leads_to_viable_head`
                        // returning `false` for *valid* ancestors of invalid blocks.
                        node.best_child = None;
                        node.best_descendant = None;
                    }
                    // The block is already invalid, but keep going backwards to ensure all ancestors
                    // are updated.
                    ExecutionStatus::Invalid(_) => (),
                    // This block is pre-merge, therefore it has no execution status. Nor do its
                    // ancestors.
                    ExecutionStatus::Irrelevant(_) => break,
                }
            }

            if let Some(parent_index) = node.parent {
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

            if let Some(parent_index) = node.parent {
                if invalidated_indices.contains(&parent_index) {
                    match &node.execution_status {
                        ExecutionStatus::Valid(hash) => {
                            return Err(Error::ValidExecutionStatusBecameInvalid {
                                block_root: node.root,
                                payload_block_hash: *hash,
                            })
                        }
                        ExecutionStatus::Optimistic(hash) | ExecutionStatus::Invalid(hash) => {
                            node.execution_status = ExecutionStatus::Invalid(*hash)
                        }
                        ExecutionStatus::Irrelevant(_) => {
                            return Err(Error::IrrelevantDescendant {
                                block_root: node.root,
                            })
                        }
                    }

                    invalidated_indices.insert(index);
                }
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
        //
        // Fork choice is effectively broken until a new justified root is set. It might not be
        // practically possible to set a new justified root if we are unable to find a new head.
        //
        // This scenario is *unsupported*. It represents a serious consensus failure.
        if justified_node.execution_status.is_invalid() {
            return Err(Error::InvalidJustifiedCheckpointExecutionStatus {
                justified_root: *justified_root,
            });
        }

        let best_descendant_index = justified_node.best_descendant.unwrap_or(justified_index);

        let best_node = self
            .nodes
            .get(best_descendant_index)
            .ok_or(Error::InvalidBestDescendant(best_descendant_index))?;

        // Perform a sanity check that the node is indeed valid to be the head.
        if !self.node_is_viable_for_head::<E>(best_node, current_slot) {
            return Err(Error::InvalidBestNode(Box::new(InvalidBestNodeInfo {
                current_slot,
                start_root: *justified_root,
                justified_checkpoint: self.justified_checkpoint,
                finalized_checkpoint: self.finalized_checkpoint,
                head_root: justified_node.root,
                head_justified_checkpoint: justified_node.justified_checkpoint,
                head_finalized_checkpoint: justified_node.finalized_checkpoint,
            })));
        }

        Ok(best_node.root)
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
                .root;
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
            if let Some(parent) = node.parent {
                // If `node.parent` is less than `finalized_index`, set it to `None`.
                node.parent = parent.checked_sub(finalized_index);
            }
            if let Some(best_child) = node.best_child {
                node.best_child = Some(
                    best_child
                        .checked_sub(finalized_index)
                        .ok_or(Error::IndexOverflow("best_child"))?,
                );
            }
            if let Some(best_descendant) = node.best_descendant {
                node.best_descendant = Some(
                    best_descendant
                        .checked_sub(finalized_index)
                        .ok_or(Error::IndexOverflow("best_descendant"))?,
                );
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
    ///     best-descendant.
    /// - The child is not the best child but becomes the best child.
    /// - The child is not the best child and does not become the best child.
    fn maybe_update_best_child_and_descendant<E: EthSpec>(
        &mut self,
        parent_index: usize,
        child_index: usize,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let child = self
            .nodes
            .get(child_index)
            .ok_or(Error::InvalidNodeIndex(child_index))?;

        let parent = self
            .nodes
            .get(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;

        let child_leads_to_viable_head =
            self.node_leads_to_viable_head::<E>(child, current_slot)?;

        // These three variables are aliases to the three options that we may set the
        // `parent.best_child` and `parent.best_descendant` to.
        //
        // I use the aliases to assist readability.
        let change_to_none = (None, None);
        let change_to_child = (
            Some(child_index),
            child.best_descendant.or(Some(child_index)),
        );
        let no_change = (parent.best_child, parent.best_descendant);

        let (new_best_child, new_best_descendant) =
            if let Some(best_child_index) = parent.best_child {
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

                    let best_child_leads_to_viable_head =
                        self.node_leads_to_viable_head::<E>(best_child, current_slot)?;

                    if child_leads_to_viable_head && !best_child_leads_to_viable_head {
                        // The child leads to a viable head, but the current best-child doesn't.
                        change_to_child
                    } else if !child_leads_to_viable_head && best_child_leads_to_viable_head {
                        // The best child leads to a viable head, but the child doesn't.
                        no_change
                    } else if child.weight == best_child.weight {
                        // Tie-breaker of equal weights by root.
                        if child.root >= best_child.root {
                            change_to_child
                        } else {
                            no_change
                        }
                    } else {
                        // Choose the winner by weight.
                        if child.weight >= best_child.weight {
                            change_to_child
                        } else {
                            no_change
                        }
                    }
                }
            } else if child_leads_to_viable_head {
                // There is no current best-child and the child is viable.
                change_to_child
            } else {
                // There is no current best-child but the child is not viable.
                no_change
            };

        let parent = self
            .nodes
            .get_mut(parent_index)
            .ok_or(Error::InvalidNodeIndex(parent_index))?;

        parent.best_child = new_best_child;
        parent.best_descendant = new_best_descendant;

        Ok(())
    }

    /// Indicates if the node itself is viable for the head, or if it's best descendant is viable
    /// for the head.
    fn node_leads_to_viable_head<E: EthSpec>(
        &self,
        node: &ProtoNode,
        current_slot: Slot,
    ) -> Result<bool, Error> {
        let best_descendant_is_viable_for_head =
            if let Some(best_descendant_index) = node.best_descendant {
                let best_descendant = self
                    .nodes
                    .get(best_descendant_index)
                    .ok_or(Error::InvalidBestDescendant(best_descendant_index))?;

                self.node_is_viable_for_head::<E>(best_descendant, current_slot)
            } else {
                false
            };

        Ok(best_descendant_is_viable_for_head
            || self.node_is_viable_for_head::<E>(node, current_slot))
    }

    /// This is the equivalent to the `filter_block_tree` function in the eth2 spec:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/fork-choice.md#filter_block_tree
    ///
    /// Any node that has a different finalized or justified epoch should not be viable for the
    /// head.
    fn node_is_viable_for_head<E: EthSpec>(&self, node: &ProtoNode, current_slot: Slot) -> bool {
        if node.execution_status.is_invalid() {
            return false;
        }

        let genesis_epoch = Epoch::new(0);

        let checkpoint_match_predicate =
            |node_justified_checkpoint: Checkpoint, node_finalized_checkpoint: Checkpoint| {
                let correct_justified = node_justified_checkpoint == self.justified_checkpoint
                    || self.justified_checkpoint.epoch == genesis_epoch;
                let correct_finalized = node_finalized_checkpoint == self.finalized_checkpoint
                    || self.finalized_checkpoint.epoch == genesis_epoch;
                correct_justified && correct_finalized
            };

        if let (
            Some(unrealized_justified_checkpoint),
            Some(unrealized_finalized_checkpoint),
            Some(justified_checkpoint),
            Some(finalized_checkpoint),
        ) = (
            node.unrealized_justified_checkpoint,
            node.unrealized_finalized_checkpoint,
            node.justified_checkpoint,
            node.finalized_checkpoint,
        ) {
            let current_epoch = current_slot.epoch(E::slots_per_epoch());

            // If previous epoch is justified, pull up all tips to at least the previous epoch
            if CountUnrealizedFull::True == self.count_unrealized_full
                && (current_epoch > genesis_epoch
                    && self.justified_checkpoint.epoch + 1 == current_epoch)
            {
                unrealized_justified_checkpoint.epoch + 1 >= current_epoch
            // If previous epoch is not justified, pull up only tips from past epochs up to the current epoch
            } else {
                // If block is from a previous epoch, filter using unrealized justification & finalization information
                if node.slot.epoch(E::slots_per_epoch()) < current_epoch {
                    checkpoint_match_predicate(
                        unrealized_justified_checkpoint,
                        unrealized_finalized_checkpoint,
                    )
                // If block is from the current epoch, filter using the head state's justification & finalization information
                } else {
                    checkpoint_match_predicate(justified_checkpoint, finalized_checkpoint)
                }
            }
        } else if let (Some(justified_checkpoint), Some(finalized_checkpoint)) =
            (node.justified_checkpoint, node.finalized_checkpoint)
        {
            checkpoint_match_predicate(justified_checkpoint, finalized_checkpoint)
        } else {
            false
        }
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
            .map(|node| (node.root, node.slot))
    }

    /// Returns `true` if the `descendant_root` has an ancestor with `ancestor_root`. Always
    /// returns `false` if either input root is unknown.
    ///
    /// ## Notes
    ///
    /// Still returns `true` if `ancestor_root` is known and `ancestor_root == descendant_root`.
    pub fn is_descendant(&self, ancestor_root: Hash256, descendant_root: Hash256) -> bool {
        self.indices
            .get(&ancestor_root)
            .and_then(|ancestor_index| self.nodes.get(*ancestor_index))
            .and_then(|ancestor| {
                self.iter_block_roots(&descendant_root)
                    .take_while(|(_root, slot)| *slot >= ancestor.slot)
                    .find(|(_root, slot)| *slot == ancestor.slot)
                    .map(|(root, _slot)| root == ancestor_root)
            })
            .unwrap_or(false)
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
                node.execution_status
                    .block_hash()
                    .map_or(false, |node_block_hash| node_block_hash == *block_hash)
            })
            .map(|node| node.root)
    }
}

/// A helper method to calculate the proposer boost based on the given `validator_balances`.
/// This does *not* do any verification about whether a boost should or should not be applied.
/// The `validator_balances` array used here is assumed to be structured like the one stored in
/// the `BalancesCache`, where *effective* balances are stored and inactive balances are defaulted
/// to zero.
///
/// Returns `None` if there is an overflow or underflow when calculating the score.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/fork-choice.md#get_latest_attesting_balance
pub fn calculate_proposer_boost<E: EthSpec>(
    validator_balances: &[u64],
    proposer_score_boost: u64,
) -> Option<u64> {
    let mut total_balance: u64 = 0;
    let mut num_validators: u64 = 0;
    for &balance in validator_balances {
        // We need to filter zero balances here to get an accurate active validator count.
        // This is because we default inactive validator balances to zero when creating
        // this balances array.
        if balance != 0 {
            total_balance = total_balance.checked_add(balance)?;
            num_validators = num_validators.checked_add(1)?;
        }
    }
    let average_balance = total_balance.checked_div(num_validators)?;
    let committee_size = num_validators.checked_div(E::slots_per_epoch())?;
    let committee_weight = committee_size.checked_mul(average_balance)?;
    committee_weight
        .checked_mul(proposer_score_boost)?
        .checked_div(100)
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
        self.next_node_index = node.parent;
        Some(node)
    }
}
