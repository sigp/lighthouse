use crate::Error;
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use types::{Epoch, Hash256};

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
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
    pub fn is_better_than(&self, other: &Self) -> bool {
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
        finalized_epoch: Epoch,
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
        self.ffg_update_required =
            justified_epoch != self.justified_epoch || finalized_epoch != self.finalized_epoch;
        if self.ffg_update_required {
            self.justified_epoch = justified_epoch;
            self.finalized_epoch = finalized_epoch;
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

                self.maybe_update_best_child_and_descendant(parent_index, node_index)?;

                /*
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
                        .is_better_than(parent_best_child);

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
                */
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
        parent_opt: Option<Hash256>,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
    ) -> Result<(), Error> {
        let node_index = self.nodes.len();

        let node = ProtoNode {
            root,
            parent: parent_opt.and_then(|parent| self.indices.get(&parent).copied()),
            justified_epoch,
            finalized_epoch,
            weight: 0,
            best_child: None,
            best_descendant: None,
        };

        self.indices.insert(node.root, node_index);
        self.nodes.push(node.clone());

        if let Some(parent_index) = node.parent {
            self.maybe_update_best_child_and_descendant(parent_index, node_index)?;
        }

        /*
        // If the blocks justified and finalized epochs match our values, then try and see if it
        // becomes the best child.
        if self.node_is_viable_for_head(&node) {
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

                    if node.is_better_than(parent_best_child) {
                        self.set_best_child(parent_index, node_index)?;
                    }
                } else {
                    self.set_best_child(parent_index, node_index)?;
                };
            }
        }
        */

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
            .ok_or_else(|| Error::JustifiedNodeUnknown(*justified_root))?;

        let justified_node = self
            .nodes
            .get(justified_index)
            .ok_or_else(|| Error::InvalidJustifiedIndex(justified_index))?;

        let best_descendant_index = justified_node
            .best_descendant
            .unwrap_or_else(|| justified_index);

        let best_node = self
            .nodes
            .get(best_descendant_index)
            .ok_or_else(|| Error::InvalidBestDescendant(best_descendant_index))?;

        // It is a logic error to try and find the head starting from a block that does not match
        // the filter.
        if !self.node_is_viable_for_head(&best_node) {
            return Err(Error::InvalidBestNode {
                justified_epoch: self.justified_epoch,
                finalized_epoch: self.finalized_epoch,
                node_justified_epoch: justified_node.justified_epoch,
                node_finalized_epoch: justified_node.finalized_epoch,
            });
        }

        // dbg!(&self.nodes);

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
        if finalized_epoch < self.finalized_epoch {
            // It's illegal to swap to an earlier finalized root (this is assumed to be reverting a
            // finalized block).
            return Err(Error::RevertedFinalizedEpoch);
        } else if finalized_epoch != self.finalized_epoch {
            self.finalized_epoch = finalized_epoch;
            self.ffg_update_required = true;
        }

        let finalized_index = *self
            .indices
            .get(&finalized_root)
            .ok_or_else(|| Error::FinalizedNodeUnknown(finalized_root))?;

        if finalized_index < self.prune_threshold {
            // Pruning at small numbers incurs more cost than benefit.
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

        // Adjust the indices map.
        for (_root, index) in self.indices.iter_mut() {
            *index = index
                .checked_sub(finalized_index)
                .ok_or_else(|| Error::IndexOverflow("indices"))?;
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
        }

        Ok(())
    }

    fn maybe_update_best_child_and_descendant(
        &mut self,
        parent_index: usize,
        child_index: usize,
    ) -> Result<(), Error> {
        let child = self
            .nodes
            .get(child_index)
            .ok_or_else(|| Error::InvalidNodeIndex(child_index))?;

        let parent = self
            .nodes
            .get(parent_index)
            .ok_or_else(|| Error::InvalidNodeIndex(parent_index))?;

        let child_leads_to_viable_head = self.node_leads_to_viable_head(&child)?;

        let change_to_none = (None, None);
        let change_to_child = (
            Some(child_index),
            child.best_descendant.or(Some(child_index)),
        );
        let no_change = (parent.best_child, parent.best_descendant);

        let (new_best_child, new_best_descendant) =
            match (parent.best_child, parent.best_descendant) {
                (None, None) => {
                    if child_leads_to_viable_head {
                        change_to_child
                    } else {
                        no_change
                    }
                }
                (Some(best_child_index), Some(best_descendant_index)) => {
                    if best_child_index == child_index && !child_leads_to_viable_head {
                        change_to_none
                    } else if best_child_index == child_index {
                        change_to_child
                    } else {
                        let best_child = self
                            .nodes
                            .get(best_child_index)
                            .ok_or_else(|| Error::InvalidBestDescendant(best_child_index))?;
                        /*
                        let best_descendant = self
                            .nodes
                            .get(best_descendant_index)
                            .ok_or_else(|| Error::InvalidBestDescendant(best_descendant_index))?;
                        */

                        let child_leads_to_viable_head = self.node_leads_to_viable_head(&child)?;
                        let best_child_leads_to_viable_head =
                            self.node_leads_to_viable_head(&best_child)?;

                        if child_leads_to_viable_head && !best_child_leads_to_viable_head {
                            change_to_child
                        } else if !child_leads_to_viable_head && best_child_leads_to_viable_head {
                            no_change
                        } else if child.weight == best_child.weight {
                            if child.root >= best_child.root {
                                change_to_child
                            } else {
                                no_change
                            }
                        } else {
                            if child.weight >= best_child.weight {
                                change_to_child
                            } else {
                                no_change
                            }
                        }
                    }
                }
                _ => return Err(Error::BestDescendantWithoutBestChild),
            };

        /*
        dbg!((
            child_index,
            parent_index,
            new_best_child,
            new_best_descendant
        ));
        */

        let parent = self
            .nodes
            .get_mut(parent_index)
            .ok_or_else(|| Error::InvalidNodeIndex(parent_index))?;

        parent.best_child = new_best_child;
        parent.best_descendant = new_best_descendant;

        /*
        let new_best_descendant = if let Some(parent_best_descendant_index) = parent.best_descendant
        {
            if parent_best_descendant_index == child_index && !child_leads_to_viable_head {
                None
            } else if parent_best_descendant_index != child_index {
                let parent_best_descendant = self
                    .nodes
                    .get(parent_best_descendant_index)
                    .ok_or_else(|| Error::InvalidBestDescendant(parent_best_descendant_index))?;

                let child_leads_to_viable_head = self.node_leads_to_viable_head(&child)?;
                let parent_best_descendant_leads_to_viable_head =
                    self.node_leads_to_viable_head(&parent_best_descendant)?;

                if child_leads_to_viable_head && !parent_best_descendant_leads_to_viable_head {
                    Some(child_index)
                } else if !child_leads_to_viable_head && parent_best_descendant_leads_to_viable_head
                {
                    Some(parent_best_descendant_index)
                } else if child.weight == parent_best_descendant.weight {
                    if child.root >= parent_best_descendant.root {
                        Some(child_index)
                    } else {
                        Some(parent_best_descendant_index)
                    }
                } else {
                    if child.weight >= parent_best_descendant.weight {
                        Some(child_index)
                    } else {
                        Some(parent_best_descendant_index)
                    }
                }
            } else {
                Some(child_index)
            }
        } else {
            if child_leads_to_viable_head {
                // If the parent does not have a best-descendant and the child is viable, then it's
                // the best by default.
                Some(child_index)
            } else {
                // If the parent does not have a best-descendant but the child is not viable, then
                // leave the parent with no best-descendant.
                None
            }
        };

        let parent = self
            .nodes
            .get_mut(parent_index)
            .ok_or_else(|| Error::InvalidNodeIndex(parent_index))?;

        dbg!(new_best_descendant);

        match new_best_descendant {
            None => {
                parent.best_child = None;
                parent.best_descendant = None;
            }
            Some(index) if index == child_index => {
                parent.best_child = Some(child_index);
                parent.best_descendant = match child_best_descendant {
                    Some(index) => Some(index),
                    None => Some(child_index),
                };
            }
            _ => {}
        }
        */

        Ok(())
    }

    fn node_leads_to_viable_head(&self, node: &ProtoNode) -> Result<bool, Error> {
        let best_descendant_is_viable_for_head =
            if let Some(best_descendant_index) = node.best_descendant {
                let best_descendant = self
                    .nodes
                    .get(best_descendant_index)
                    .ok_or_else(|| Error::InvalidBestDescendant(best_descendant_index))?;

                self.node_is_viable_for_head(best_descendant)
            } else {
                false
            };

        Ok(best_descendant_is_viable_for_head || self.node_is_viable_for_head(node))
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
        (node.justified_epoch == self.justified_epoch || self.justified_epoch == Epoch::new(0))
            && (node.finalized_epoch == self.finalized_epoch
                || self.finalized_epoch == Epoch::new(0))
    }
}
