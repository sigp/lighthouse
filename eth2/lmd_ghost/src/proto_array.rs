use crate::LmdGhost;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use types::{BeaconBlock, BeaconState, Epoch, EthSpec, Hash256, Slot};

pub const PRUNE_THRESHOLD: usize = 200;

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    FinalizedNodeUnknown(Hash256),
    JustifiedNodeUnknown(Hash256),
    InvalidFinalizedRootChange,
    InvalidNodeIndex(usize),
    InvalidParentIndex(usize),
    InvalidBestChildIndex(usize),
    InvalidJustifiedIndex(usize),
    InvalidBestDescendant(usize),
    InvalidParentDelta(usize),
    InvalidNodeDelta(usize),
    DeltaOverflow(usize),
    IndexOverflow(&'static str),
    InvalidDeltaLen { deltas: usize, indices: usize },
    RevertedFinalizedEpoch,
    InvalidFindHeadStartRoot,
}

#[derive(Default, PartialEq, Clone)]
pub struct VoteTracker {
    current_root: Hash256,
    next_root: Hash256,
    next_epoch: Epoch,
}

pub struct ProtoArrayForkChoice {
    proto_array: RwLock<ProtoArray>,
    votes: RwLock<ElasticList<VoteTracker>>,
    balances: RwLock<Vec<u64>>,
}

impl PartialEq for ProtoArrayForkChoice {
    fn eq(&self, other: &Self) -> bool {
        *self.proto_array.read() == *other.proto_array.read()
            && *self.votes.read() == *other.votes.read()
            && *self.balances.read() == *other.balances.read()
    }
}

impl LmdGhost for ProtoArrayForkChoice {
    fn new(
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
    ) -> Result<Self, String> {
        let mut proto_array = ProtoArray {
            ffg_update_required: false,
            justified_epoch,
            finalized_epoch,
            finalized_root,
            nodes: Vec::with_capacity(1),
            indices: HashMap::with_capacity(1),
        };

        proto_array
            .on_new_block(finalized_root, None, justified_epoch, finalized_epoch)
            .map_err(|e| format!("Failed to add finalized block to proto_array: {:?}", e))?;

        Ok(Self {
            proto_array: RwLock::new(proto_array),
            votes: RwLock::new(ElasticList::default()),
            balances: RwLock::new(vec![]),
        })
    }

    fn process_attestation(
        &self,
        validator_index: usize,
        block_root: Hash256,
        block_epoch: Epoch,
    ) -> Result<(), String> {
        let mut votes = self.votes.write();

        if block_epoch > votes.get(validator_index).next_epoch {
            let vote = votes.get_mut(validator_index);
            vote.next_root = block_root;
            vote.next_epoch = block_epoch;
        }

        Ok(())
    }

    fn process_block(
        &self,
        block_root: Hash256,
        parent_root: Hash256,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
    ) -> Result<(), String> {
        self.proto_array
            .write()
            .on_new_block(
                block_root,
                Some(parent_root),
                justified_epoch,
                finalized_epoch,
            )
            .map_err(|e| format!("process_block_error: {:?}", e))
    }

    fn find_head(
        &self,
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        justified_state_balances: &[u64],
    ) -> Result<Hash256, String> {
        let mut proto_array = self.proto_array.write();
        let mut votes = self.votes.write();
        let mut old_balances = self.balances.write();

        let new_balances = justified_state_balances;

        let deltas = compute_deltas(
            &proto_array.indices,
            &mut votes,
            &old_balances,
            &new_balances,
        )
        .map_err(|e| format!("find_head compute_deltas failed: {:?}", e))?;

        proto_array
            .maybe_prune(finalized_epoch, finalized_root)
            .map_err(|e| format!("find_head maybe_prune failed: {:?}", e))?;
        proto_array
            .apply_score_changes(deltas, justified_epoch)
            .map_err(|e| format!("find_head apply_score_changes failed: {:?}", e))?;

        *old_balances = new_balances.to_vec();

        proto_array
            .find_head(&justified_root)
            .map_err(|e| format!("find_head failed: {:?}", e))
    }

    fn update_finalized_root(
        &self,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
    ) -> Result<(), String> {
        self.proto_array
            .write()
            .maybe_prune(finalized_epoch, finalized_root)
            .map_err(|e| format!("find_head maybe_prune failed: {:?}", e))
    }

    fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Slot)> {
        unimplemented!()
    }

    fn verify_integrity(&self) -> Result<(), String> {
        unimplemented!()
    }

    fn as_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        unimplemented!()
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
/// always valid).
fn compute_deltas(
    indices: &HashMap<Hash256, usize>,
    votes: &mut ElasticList<VoteTracker>,
    old_balances: &[u64],
    new_balances: &[u64],
) -> Result<Vec<i64>, Error> {
    let mut deltas = vec![0_i64; indices.len()];

    for (val_index, vote) in votes.iter_mut().enumerate() {
        // There is no need to create a score change if the validator has never voted or both their
        // votes are for the zero hash (alias to the genesis block).
        if vote.current_root == Hash256::zero() && vote.next_root == Hash256::zero() {
            continue;
        }

        // If the validator was not included in the _old_ balances (i.e., it did not exist yet)
        // then say its balance was zero.
        let old_balance = old_balances.get(val_index).copied().unwrap_or_else(|| 0);

        // If the validators vote is not known in the _new_ balances, then use a balance of zero.
        //
        // It is possible that there is a vote for an unknown validator if we change our justified
        // state to a new state with a higher epoch that is on a different fork because that fork may have
        // on-boarded less validators than the prior fork.
        let new_balance = new_balances.get(val_index).copied().unwrap_or_else(|| 0);

        if vote.current_root != vote.next_root || old_balance != new_balance {
            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(current_delta_index) = indices.get(&vote.current_root).copied() {
                let delta = deltas
                    .get_mut(current_delta_index)
                    .ok_or_else(|| Error::InvalidNodeDelta(current_delta_index))?
                    .checked_sub(old_balance as i64)
                    .ok_or_else(|| Error::DeltaOverflow(current_delta_index))?;

                // Array access safe due to check on previous line.
                deltas[current_delta_index] = delta;
            }

            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(next_delta_index) = indices.get(&vote.next_root).copied() {
                let delta = deltas
                    .get(next_delta_index)
                    .ok_or_else(|| Error::InvalidNodeDelta(next_delta_index))?
                    .checked_add(new_balance as i64)
                    .ok_or_else(|| Error::DeltaOverflow(next_delta_index))?;

                // Array access safe due to check on previous line.
                deltas[next_delta_index] = delta;
            }

            vote.current_root = vote.next_root;
        }
    }

    Ok(deltas)
}

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
    /// Set to true when the Casper FFG justified/finalized epochs should be checked to ensure the
    /// tree is filtered as per eth2 specs.
    ffg_update_required: bool,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    finalized_root: Hash256,
    nodes: Vec<ProtoNode>,
    indices: HashMap<Hash256, usize>,
}

impl ProtoArray {
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

        self.ffg_update_required = justified_epoch != self.justified_epoch;
        if self.ffg_update_required {
            self.justified_epoch = justified_epoch;
        }

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

            if node_delta < 0 {
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

            if let Some(parent_index) = node.parent {
                if parent_index > 0 {
                    let parent_delta = deltas
                        .get_mut(parent_index)
                        .ok_or_else(|| Error::InvalidParentDelta(parent_index))?;

                    *parent_delta += node_delta;
                }

                let is_viable_for_head = self
                    .nodes
                    .get(node_index)
                    .map(|node| self.node_is_viable_for_head(node))
                    .ok_or_else(|| Error::InvalidNodeIndex(parent_index))?;

                if !is_viable_for_head {
                    // If the given node is not viable for the head and we are required to check
                    // for FFG changes, then check to see if the child is presently set to the best
                    // child for the parent. If so, remove the best-child link because this node is
                    // not viable.
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

                    if self
                        .nodes
                        .get(node_index)
                        .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                        .is_better_then(parent_best_child)
                    {
                        self.set_best_child(parent_index, node_index)?;
                    }
                } else {
                    self.set_best_child(parent_index, node_index)?;
                };
            }
        }

        self.ffg_update_required = false;

        Ok(())
    }

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

    pub fn maybe_prune(
        &mut self,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
    ) -> Result<(), Error> {
        if finalized_epoch == self.finalized_epoch && finalized_root == self.finalized_root {
            return Ok(());
        } else if finalized_epoch == self.finalized_epoch && self.finalized_root != finalized_root {
            return Err(Error::InvalidFinalizedRootChange);
        } else if finalized_epoch < self.finalized_epoch {
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
        if finalized_index < PRUNE_THRESHOLD {
            return Ok(());
        }

        for node_index in 0..finalized_index {
            let root = &self
                .nodes
                .get(node_index)
                .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                .root;
            self.indices.remove(root);
        }

        self.nodes = self.nodes.split_off(finalized_index);

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

    fn node_is_viable_for_head(&self, node: &ProtoNode) -> bool {
        node.justified_epoch == self.justified_epoch && node.finalized_epoch == self.finalized_epoch
    }
}

/// A Vec-wrapper which will grow to match any request.
///
/// E.g., a `get` or `insert` to an out-of-bounds element will cause the Vec to grow (using
/// Default) to the smallest size required to fulfill the request.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ElasticList<T>(Vec<T>);

impl<T> ElasticList<T>
where
    T: Default,
{
    fn ensure(&mut self, i: usize) {
        if self.0.len() <= i {
            self.0.resize_with(i + 1, Default::default);
        }
    }

    pub fn get(&mut self, i: usize) -> &T {
        self.ensure(i);
        &self.0[i]
    }

    pub fn get_mut(&mut self, i: usize) -> &mut T {
        self.ensure(i);
        &mut self.0[i]
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod test_compute_deltas {
    use super::*;

    /// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
    fn hash_from_index(i: usize) -> Hash256 {
        Hash256::from_low_u64_be(i as u64 + 1)
    }

    #[test]
    fn zero_hash() {
        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: Hash256::zero(),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(0);
            new_balances.push(0);
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(0),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(i),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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

        // There is only one block.
        indices.insert(hash_from_index(1), 0);

        // There are two validators.
        let old_balances = vec![BALANCE; 2];
        let new_balances = vec![BALANCE; 2];

        // One validator moves their vote from the block to the zero hash.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::zero(),
            next_epoch: Epoch::new(0),
        });

        // One validator moves their vote from the block to something outside the tree.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::from_low_u64_be(1337),
            next_epoch: Epoch::new(0),
        });

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(OLD_BALANCE);
            new_balances.push(NEW_BALANCE);
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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
                next_epoch: Epoch::new(0),
            });
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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
                next_epoch: Epoch::new(0),
            });
        }

        let deltas = compute_deltas(&indices, &mut votes, &old_balances, &new_balances)
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
                "the vote shoulds should have been updated"
            );
        }
    }
}

#[cfg(test)]
mod test_proto_array_fork_choice {
    use super::*;

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
