use crate::Error;
use std::collections::HashMap;
use types::{Epoch, Hash256};

#[derive(Clone, PartialEq, Debug)]
pub struct ProtoNode {
    root: Hash256,
    parent: Option<usize>,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    weight: u64,
    best_child: Option<usize>,
    best_descendant: Option<usize>,
}

impl ProtoNode {
    /// Returns `true` if some node is "better" than the other, according to either weight or root.
    ///
    /// If `self == other`, then `true` is returned.
    pub fn is_better_then(&self, other: &Self) -> bool {
        if self.weight == other.weight {
            self.root >= other.root
        } else {
            self.weight >= other.weight
        }
    }
}

#[derive(PartialEq)]
pub struct ProtoArray {
    /// Do not attempt to prune the tree unless it has at least this many nodes. Small prunes
    /// simply waste time.
    pub prune_threshold: usize,
    /// Set to true when the Casper FFG justified/finalized epochs should be checked to ensure the
    /// tree is filtered as per eth2 specs.
    pub ffg_update_required: bool,
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,
    pub nodes: Vec<ProtoNode>,
    pub indices: HashMap<Hash256, usize>,
}

impl ProtoArray {
    /// Iterate backwards through the array, touching all nodes and their parents and potentially
    /// the best-child of each parent.
    ///
    /// The structure of the `self.nodes` array ensures that the child of each node is always
    /// touched before it's parent.
    ///
    /// For each node, the following is done:
    ///
    /// - Update the nodes weight with the corresponding delta.
    /// - Back-propgrate each nodes delta to its parents delta.
    /// - Compare the current node with the parents best-child, updating it if the current node
    /// should become the best child.
    /// - Update the parents best-descendant with the current node or its best-descendant, if
    /// required.
    pub fn apply_score_changes(
        &mut self,
        mut deltas: Vec<i64>,
        justified_epoch: Epoch,
    ) -> Result<(), Error> {
        if deltas.len() != self.indices.len() {
            return Err(Error::InvalidDeltaLen {
                deltas: deltas.len(),
                indices: self.indices.len(),
            });
        }

        // The `self.ffg_update_required` flag indicates if it is necessary to check the
        // finalized/justified epoch of all nodes against the epochs in `self`.
        //
        // This behaviour is equivalent to the `filter_block_tree` function in the spec.
        self.ffg_update_required = justified_epoch != self.justified_epoch;
        if self.ffg_update_required {
            self.justified_epoch = justified_epoch;
        }

        // Iterate backwards through all indices in `self.nodes`.
        for node_index in (0..self.nodes.len()).rev() {
            let node = &mut self
                .nodes
                .get_mut(node_index)
                .ok_or_else(|| Error::InvalidNodeIndex(node_index))?;

            // There is no need to adjust the balances or manage parent of the zero hash since it
            // is an alias to the genesis block. The weight applied to the genesis block is
            // irrelevant as we _always_ choose it and it's impossible for it to have a parent.
            if node.root == Hash256::zero() {
                continue;
            }

            let node_delta = deltas
                .get(node_index)
                .copied()
                .ok_or_else(|| Error::InvalidNodeDelta(node_index))?;

            // Apply the delta to the node.
            if node_delta < 0 {
                // Note: I am conflicted about wether to use `saturating_sub` or `checked_sub`
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
                    .checked_sub(node_delta.abs() as u64)
                    .ok_or_else(|| Error::DeltaOverflow(node_index))?;
            } else {
                node.weight = node
                    .weight
                    .checked_add(node_delta as u64)
                    .ok_or_else(|| Error::DeltaOverflow(node_index))?;
            }

            // If the node has a parent, try to update its best-child and best-descendant.
            if let Some(parent_index) = node.parent {
                let parent_delta = deltas
                    .get_mut(parent_index)
                    .ok_or_else(|| Error::InvalidParentDelta(parent_index))?;

                // Back-propogate the nodes delta to its parent.
                *parent_delta += node_delta;

                let is_viable_for_head = self
                    .nodes
                    .get(node_index)
                    .map(|node| self.node_is_viable_for_head(node))
                    .ok_or_else(|| Error::InvalidNodeIndex(parent_index))?;

                // If the given node is _not viable_ for the head and we are required to check
                // for FFG changes, then remove the child if it is currently the parents
                // best-child.
                if !is_viable_for_head {
                    if self.ffg_update_required {
                        let parent_best_child = self
                            .nodes
                            .get(parent_index)
                            .ok_or_else(|| Error::InvalidParentIndex(parent_index))?
                            .best_child;

                        if parent_best_child == Some(node_index) {
                            let parent_node = self
                                .nodes
                                .get_mut(parent_index)
                                .ok_or_else(|| Error::InvalidParentIndex(parent_index))?;

                            parent_node.best_child = None;
                            parent_node.best_descendant = None;
                        }
                    }

                    continue;
                }

                // If the parent has a best-child, see if the current node is better. If it doesn't
                // have a best child, set it to ours.
                //
                // Note: this code only runs if the node is viable for the head due to `continue`
                // call in previous statement.
                if let Some(parent_best_child_index) = self
                    .nodes
                    .get(parent_index)
                    .ok_or_else(|| Error::InvalidParentIndex(parent_index))?
                    .best_child
                {
                    // Here we set the best child to `node_index` when that is already the case.
                    // This has the effect of ensuring the `best_descendant` is updated.
                    if parent_best_child_index == node_index {
                        self.set_best_child(parent_index, node_index)?;
                        continue;
                    }

                    let parent_best_child = self
                        .nodes
                        .get(parent_best_child_index)
                        .ok_or_else(|| Error::InvalidBestChildIndex(parent_best_child_index))?;

                    let node_is_better_than_current_best_child = self
                        .nodes
                        .get(node_index)
                        .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                        .is_better_then(parent_best_child);

                    let current_best_child_is_viable =
                        self.node_is_viable_for_head(parent_best_child);

                    // There are two conditions for replacing a best child:
                    //
                    // - The node is better than the present best-child.
                    // - The present best-child in no longer viable (viz., it has been filtered out).
                    if node_is_better_than_current_best_child || !current_best_child_is_viable {
                        self.set_best_child(parent_index, node_index)?;
                    }
                } else {
                    // If the best child is `None`, simply set it to the current node (noting that
                    // this code only runs if the current node is viable for the head).
                    self.set_best_child(parent_index, node_index)?;
                };
            }
        }

        self.ffg_update_required = false;

        Ok(())
    }

    /// Register a new block with the fork choice.
    ///
    /// It is only sane to supply a `None` parent for the genesis block.
    pub fn on_new_block(
        &mut self,
        root: Hash256,
        parent: Option<Hash256>,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
    ) -> Result<(), Error> {
        let node_index = self.nodes.len();

        let node = ProtoNode {
            root,
            parent: parent.and_then(|parent_root| self.indices.get(&parent_root).copied()),
            justified_epoch,
            finalized_epoch,
            weight: 0,
            best_child: None,
            best_descendant: None,
        };

        self.indices.insert(node.root, node_index);
        self.nodes.push(node.clone());

        // If the blocks justified and finalized epochs match our values, then try and see if it
        // becomes the best child.
        if justified_epoch == self.justified_epoch && finalized_epoch == self.finalized_epoch {
            if let Some(parent_index) = node.parent {
                let parent = self
                    .nodes
                    .get(parent_index)
                    .ok_or_else(|| Error::InvalidParentIndex(parent_index))?;

                if let Some(parent_best_child_index) = parent.best_child {
                    let parent_best_child = self
                        .nodes
                        .get(parent_best_child_index)
                        .ok_or_else(|| Error::InvalidBestChildIndex(parent_best_child_index))?;

                    if node.is_better_then(parent_best_child) {
                        self.set_best_child(parent_index, node_index)?;
                    }
                } else {
                    self.set_best_child(parent_index, node_index)?;
                };
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
    pub fn find_head(&self, justified_root: &Hash256) -> Result<Hash256, Error> {
        let justified_index = self
            .indices
            .get(justified_root)
            .copied()
            .ok_or_else(|| Error::JustifiedNodeUnknown(self.finalized_root))?;

        let justified_node = self
            .nodes
            .get(justified_index)
            .ok_or_else(|| Error::InvalidJustifiedIndex(justified_index))?;

        // It is a logic error to try and find the head starting from a block that does not match
        // the filter.
        if justified_node.justified_epoch != self.justified_epoch
            || justified_node.finalized_epoch != self.finalized_epoch
        {
            return Err(Error::InvalidFindHeadStartRoot);
        }

        let best_descendant_index = justified_node
            .best_descendant
            .unwrap_or_else(|| justified_index);

        let best_node = self
            .nodes
            .get(best_descendant_index)
            .ok_or_else(|| Error::InvalidBestDescendant(best_descendant_index))?;

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
    pub fn maybe_prune(
        &mut self,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
    ) -> Result<(), Error> {
        if finalized_epoch == self.finalized_epoch && finalized_root == self.finalized_root {
            // Nothing to do.
            return Ok(());
        } else if finalized_epoch == self.finalized_epoch && self.finalized_root != finalized_root {
            // It's illegal to swap finalized roots on the same epoch (this is reverting a
            // finalized block).
            return Err(Error::InvalidFinalizedRootChange);
        } else if finalized_epoch < self.finalized_epoch {
            // It's illegal to swap to an earlier finalized root (this is assumed to be reverting a
            // finalized block).
            return Err(Error::RevertedFinalizedEpoch);
        } else {
            self.finalized_epoch = finalized_epoch;
            self.finalized_root = finalized_root;
            self.ffg_update_required = true;
        }

        let finalized_index = *self
            .indices
            .get(&self.finalized_root)
            .ok_or_else(|| Error::FinalizedNodeUnknown(self.finalized_root))?;

        // Pruning at small numbers incurs more cost than benefit.
        if finalized_index < self.prune_threshold {
            return Ok(());
        }

        // Remove the `self.indices` key/values for all the to-be-deleted nodes.
        for node_index in 0..finalized_index {
            let root = &self
                .nodes
                .get(node_index)
                .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                .root;
            self.indices.remove(root);
        }

        // Drop all the nodes prior to finalization.
        self.nodes = self.nodes.split_off(finalized_index);

        // Iterate through all the existing nodes and adjust their indicies to match the new layout
        // of `self.nodes`.
        self.nodes.iter_mut().try_for_each(|node| {
            if let Some(parent) = node.parent {
                // If `node.parent` is less than `finalized_index`, set it to `None`.
                node.parent = parent.checked_sub(finalized_index);
            }
            if let Some(best_child) = node.best_child {
                node.best_child = Some(
                    best_child
                        .checked_sub(finalized_index)
                        .ok_or_else(|| Error::IndexOverflow("best_child"))?,
                );
            }
            if let Some(best_descendant) = node.best_descendant {
                node.best_descendant = Some(
                    best_descendant
                        .checked_sub(finalized_index)
                        .ok_or_else(|| Error::IndexOverflow("best_descendant"))?,
                );
            }

            Ok(())
        })?;

        Ok(())
    }

    /// Sets the node at `parent_index` to have a best-child pointing to `child_index`. Also
    /// updates the best-descendant.
    fn set_best_child(&mut self, parent_index: usize, child_index: usize) -> Result<(), Error> {
        let child_best_descendant = self
            .nodes
            .get(child_index)
            .ok_or_else(|| Error::InvalidNodeIndex(child_index))?
            .best_descendant;

        let parent_node = self
            .nodes
            .get_mut(parent_index)
            .ok_or_else(|| Error::InvalidParentIndex(parent_index))?;

        parent_node.best_child = Some(child_index);
        parent_node.best_descendant = if let Some(best_descendant) = child_best_descendant {
            Some(best_descendant)
        } else {
            Some(child_index)
        };

        Ok(())
    }

    /// This is the equivalent to the `filter_block_tree` function in the eth2 spec:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/fork-choice.md#filter_block_tree
    ///
    /// Any node that has a different finalized or justified epoch should not be viable for the
    /// head.
    fn node_is_viable_for_head(&self, node: &ProtoNode) -> bool {
        node.justified_epoch == self.justified_epoch && node.finalized_epoch == self.finalized_epoch
    }
}

#[cfg(test)]
mod test_proto_array_fork_choice {
    use super::*;
    use crate::ProtoArrayForkChoice;

    /// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
    fn get_hash(i: u64) -> Hash256 {
        Hash256::from_low_u64_be(i)
    }

    /// This tests does not use any validator votes, it just relies on hash-sorting to find the
    /// head.
    ///
    /// The following block graph is built and tested as each block is added (each block has the
    /// hash set to the big-endian representation of its number shown here):
    ///
    ///      0
    ///     / \
    ///     2  1
    ///     |  |
    ///     4  3
    ///     |
    ///     5 <--- justified epoch becomes 1 here, all above are 0.
    ///     |
    ///     6
    #[test]
    fn no_votes() {
        const VALIDATOR_COUNT: usize = 16;

        let fork_choice = ProtoArrayForkChoice::new(Epoch::new(0), Epoch::new(0), get_hash(0))
            .expect("should create fork choice");

        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            Hash256::zero(),
            "should find genesis block as root when there is only one block"
        );

        // Add block 2
        //
        //         0
        //        /
        //        2
        fork_choice
            .process_block(get_hash(2), get_hash(0), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure the head is 2
        //
        //         0
        //        /
        //        2 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(2),
            "should find head block with a single chain"
        );

        // Add block 1
        //
        //         0
        //        / \
        //        2  1
        fork_choice
            .process_block(get_hash(1), get_hash(0), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure the head is still 2
        //
        //         0
        //        / \
        // head-> 2  1
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(2),
            "should find the first block, not the second block (it should compare hashes)"
        );

        // Add block 3
        //
        //         0
        //        / \
        //        2  1
        //           |
        //           3
        fork_choice
            .process_block(get_hash(3), get_hash(1), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure 3 is the head
        //
        //         0
        //        / \
        //        2  1
        //           |
        //           3 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(2),
            "should find the get_hash(2) block"
        );

        // Add block 4
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        //        4  3
        fork_choice
            .process_block(get_hash(4), get_hash(2), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure the head is 4.
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        // head-> 4  3
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(4),
            "should find the get_hash(4) block"
        );

        // Ensure the head is still 4 whilst the justified epoch is 0.
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        //        4  3
        //        |
        //        5 <- justified epoch = 1
        fork_choice
            .process_block(get_hash(5), get_hash(4), Epoch::new(1), Epoch::new(0))
            .expect("should process block");

        // Ensure the head is still 4 whilst the justified epoch is 0.
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        // head-> 4  3
        //        |
        //        5
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(4),
            "should find the get_hash(4) block because the get_hash(5) should be filtered out"
        );

        // Ensure there is an error when starting from a block that has the wrong justified epoch.
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5 <- starting from 5 with justified epoch 0 should error.
        assert!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .is_err(),
            "should not allow finding head from a bad justified epoch"
        );

        // Set the justified epoch to 1 and the start block to 5 and ensure 5 is the head.
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(5),
            "should find the get_hash(5) block"
        );

        // Add block 6
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5
        //     |
        //     6
        fork_choice
            .process_block(get_hash(6), get_hash(5), Epoch::new(1), Epoch::new(0))
            .expect("should process block");

        // Ensure 6 is the head
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5
        //     |
        //     6 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &[0; VALIDATOR_COUNT]
                )
                .expect("should find head"),
            get_hash(6),
            "should find the get_hash(6) block"
        );
    }

    #[test]
    fn votes() {
        const VALIDATOR_COUNT: usize = 2;
        let balances = vec![1; VALIDATOR_COUNT];

        let fork_choice = ProtoArrayForkChoice::new(Epoch::new(0), Epoch::new(0), get_hash(0))
            .expect("should create fork choice");

        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            Hash256::zero(),
            "should find genesis block as root when there is only one block"
        );

        // Add a block with a hash of 2.
        //
        //          0
        //         /
        //        2
        fork_choice
            .process_block(get_hash(2), get_hash(0), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure that the head is 2
        //
        //          0
        //         /
        // head-> 2
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(2),
            "should find head block with a single chain"
        );

        // Add a block with a hash of 1 that comes off the genesis block (this is a fork compared
        // to the previous block).
        //
        //          0
        //         / \
        //        2   1
        fork_choice
            .process_block(get_hash(1), get_hash(0), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure that the head is 2
        //
        //          0
        //         / \
        // head-> 2   1
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(2),
            "should find get_hash(2), not get_hash(1) (it should compare hashes)"
        );

        // Add a vote to block 1
        //
        //          0
        //         / \
        //        2   1 <- +vote
        fork_choice
            .process_attestation(0, get_hash(1), Epoch::new(1))
            .expect("should process attestation");

        // Ensure that the head is now 1, beacuse 1 has a vote.
        //
        //          0
        //         / \
        //        2   1 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(1),
            "should find the get_hash(1) because it now has a vote"
        );

        // Add a vote to block 2
        //
        //           0
        //          / \
        // +vote-> 2   1
        fork_choice
            .process_attestation(1, get_hash(2), Epoch::new(1))
            .expect("should process attestation");

        // Ensure that the head is 2 since 1 and 2 both have a vote
        //
        //          0
        //         / \
        // head-> 2   1
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(2),
            "should find get_hash(2)"
        );

        // Add block 3.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        fork_choice
            .process_block(get_hash(3), get_hash(1), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure that the head is still 2
        //
        //          0
        //         / \
        // head-> 2   1
        //            |
        //            3
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(2),
            "should find get_hash(2)"
        );

        // Move validator #0 vote from 1 to 3
        //
        //          0
        //         / \
        //        2   1 <- -vote
        //            |
        //            3 <- +vote
        fork_choice
            .process_attestation(0, get_hash(3), Epoch::new(2))
            .expect("should process attestation");

        // Ensure that the head is still 2
        //
        //          0
        //         / \
        // head-> 2   1
        //            |
        //            3
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(2),
            "should find get_hash(2)"
        );

        // Move validator #1 vote from 2 to 1 (this is an equivocation, but fork choice doesn't
        // care)
        //
        //           0
        //          / \
        // -vote-> 2   1 <- +vote
        //             |
        //             3
        fork_choice
            .process_attestation(1, get_hash(1), Epoch::new(2))
            .expect("should process attestation");

        // Ensure that the head is now 3
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(3),
            "should find get_hash(3)"
        );

        // Add block 4.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        fork_choice
            .process_block(get_hash(4), get_hash(3), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Ensure that the head is now 4
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(4),
            "should find get_hash(4)"
        );

        // Add block 5, which has a justified epoch of 1.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           /
        //          5 <- justified epoch = 1
        fork_choice
            .process_block(get_hash(5), get_hash(4), Epoch::new(1), Epoch::new(0))
            .expect("should process block");

        // Ensure that 5 is filtered out and the head stays at 4.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4 <- head
        //           /
        //          5
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(4),
            "should find get_hash(4)"
        );

        // Add block 6, which has a justified epoch of 0.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6 <- justified epoch = 0
        fork_choice
            .process_block(get_hash(6), get_hash(4), Epoch::new(0), Epoch::new(0))
            .expect("should process block");

        // Move both votes to 5.
        //
        //           0
        //          / \
        //         2   1
        //             |
        //             3
        //             |
        //             4
        //            / \
        // +2 vote-> 5   6
        fork_choice
            .process_attestation(0, get_hash(5), Epoch::new(3))
            .expect("should process attestation");
        fork_choice
            .process_attestation(1, get_hash(5), Epoch::new(3))
            .expect("should process attestation");

        // Add blocks 7, 8 and 9. Adding these blocks helps test the `best_descendant`
        // functionality.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         /
        //         9
        fork_choice
            .process_block(get_hash(7), get_hash(5), Epoch::new(1), Epoch::new(0))
            .expect("should process block");
        fork_choice
            .process_block(get_hash(8), get_hash(7), Epoch::new(1), Epoch::new(0))
            .expect("should process block");
        fork_choice
            .process_block(get_hash(9), get_hash(8), Epoch::new(1), Epoch::new(0))
            .expect("should process block");

        // Ensure that 6 is the head, even though 5 has all the votes. This is testing to ensure
        // that 5 is filtered out due to a differing justified epoch.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6 <- head
        //          |
        //          7
        //          |
        //          8
        //         /
        //         9
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(0),
                    Hash256::zero(),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(6),
            "should find get_hash(6)"
        );

        // Change fork-choice justified epoch to 1, and the start block to 5 and ensure that 9 is
        // the head.
        //
        // << Change justified epoch to 1 >>
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         /
        // head-> 9
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(9),
            "should find get_hash(9)"
        );

        // Change fork-choice justified epoch to 1, and the start block to 5 and ensure that 9 is
        // the head.
        //
        // << Change justified epoch to 1 >>
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         /
        //        9 <- +2 votes
        fork_choice
            .process_attestation(0, get_hash(9), Epoch::new(4))
            .expect("should process attestation");
        fork_choice
            .process_attestation(1, get_hash(9), Epoch::new(4))
            .expect("should process attestation");

        // Add block 10
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         / \
        //        9  10
        fork_choice
            .process_block(get_hash(10), get_hash(8), Epoch::new(1), Epoch::new(0))
            .expect("should process block");

        // Double-check the head is still 9 (no diagram this time)
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(9),
            "should find get_hash(9)"
        );

        // Introduce 2 more validators into the system
        let balances = vec![1; 4];

        // Have the two new validators vote for 10
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         / \
        //        9  10 <- +2 votes
        fork_choice
            .process_attestation(2, get_hash(10), Epoch::new(4))
            .expect("should process attestation");
        fork_choice
            .process_attestation(3, get_hash(10), Epoch::new(4))
            .expect("should process attestation");

        // Check the head is now 10.
        //
        //          0
        //         / \
        //        2   1
        //            |
        //            3
        //            |
        //            4
        //           / \
        //          5   6
        //          |
        //          7
        //          |
        //          8
        //         / \
        //        9  10 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(10),
            "should find get_hash(10)"
        );

        // Set the balances of the last two validators to zero
        let balances = vec![1, 1, 0, 0];

        // Check the head is 9 again.
        //
        //          .
        //          .
        //          .
        //          |
        //          8
        //         / \
        // head-> 9  10
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(9),
            "should find get_hash(9)"
        );

        // Set the balances of the last two validators back to 1
        let balances = vec![1; 4];

        // Check the head is 10.
        //
        //          .
        //          .
        //          .
        //          |
        //          8
        //         / \
        //        9  10 <- head
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(10),
            "should find get_hash(10)"
        );

        // Remove the last two validators
        let balances = vec![1; 2];

        // Check the head is 9 again.
        //
        //          .
        //          .
        //          .
        //          |
        //          8
        //         / \
        // head-> 9  10
        assert_eq!(
            fork_choice
                .find_head(
                    Epoch::new(1),
                    get_hash(5),
                    Epoch::new(0),
                    Hash256::zero(),
                    &balances
                )
                .expect("should find head"),
            get_hash(9),
            "should find get_hash(9)"
        );
    }
}
