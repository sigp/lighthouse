/// TODO:
///
/// - Allow for filtering the block tree as per spec (this probably means storing fin/just epochs
/// in the proto_array)
use parking_lot::RwLock;
use std::collections::HashMap;
use types::{Epoch, Hash256};

pub const PRUNE_THRESHOLD: usize = 200;

pub enum Error {
    BalanceUnknown(usize),
    NodeUnknown(Hash256),
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
    RevertedFinalizedEpoch,
    StartOutOfBounds,
    IndexOutOfBounds,
    BestChildOutOfBounds { i: usize, len: usize },
    ParentOutOfBounds { i: usize, len: usize },
    BestChildInconsistent,
    WeightsInconsistent,
    ParentsInconsistent,
    BestDescendantInconsistent,
}

#[derive(Default, PartialEq, Clone)]
pub struct VoteTracker {
    current_root: Hash256,
    next_root: Hash256,
    next_epoch: Epoch,
}

pub struct BalanceSnapshot {
    state_root: Hash256,
    balances: Vec<u64>,
}

pub struct ProtoArrayForkChoice {
    proto_array: RwLock<ProtoArray>,
    votes: RwLock<ElasticList<VoteTracker>>,
    balances: RwLock<BalanceSnapshot>,
}

impl ProtoArrayForkChoice {
    pub fn process_attestation(&self, validator_index: usize, block_root: Hash256, epoch: Epoch) {
        let mut votes = self.votes.write();

        if epoch > votes.get(validator_index).next_epoch {
            let vote = votes.get_mut(validator_index);
            vote.current_root = block_root;
            vote.next_epoch = epoch;
        }
    }

    pub fn process_block(
        &self,
        root: Hash256,
        finalized_epoch: Epoch,
        justified_epoch: Epoch,
        parent_root: Hash256,
    ) -> Result<(), Error> {
        let block = DagNode {
            root,
            justified_epoch,
            finalized_epoch,
            parent: Some(parent_root),
        };

        self.proto_array.write().on_new_block(block)
    }

    pub fn find_head<F>(
        &self,
        start_block_root: Hash256,
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        latest_balances: BalanceSnapshot,
    ) -> Result<Hash256, Error> {
        // Take a clone of votes to prevent a corruption in the case that `balance_change_deltas`
        // returns an error.
        let mut votes = self.votes.read().clone();

        let score_changes =
            balance_change_deltas(&mut votes, &self.balances.read(), &latest_balances)?
                .into_iter()
                .map(|(target, score_delta)| ScoreChange {
                    target,
                    score_delta,
                })
                .collect::<Vec<_>>();

        let mut proto_array = self.proto_array.write();

        proto_array.maybe_prune(finalized_epoch, finalized_root)?;
        proto_array.apply_score_changes(&score_changes, justified_epoch)?;
        proto_array.find_head(&justified_root)
    }
}

fn balance_change_deltas(
    votes: &mut ElasticList<VoteTracker>,
    old_balances: &BalanceSnapshot,
    new_balances: &BalanceSnapshot,
) -> Result<HashMap<Hash256, i64>, Error> {
    let mut score_changes = HashMap::new();

    for (val_index, vote) in votes.iter_mut().enumerate() {
        // There is no need to create a score change if the validator has never voted or both their
        // votes are for the zero hash (alias to the genesis block).
        if vote.current_root == Hash256::zero() && vote.next_root == Hash256::zero() {
            continue;
        }

        // If the validator was not included in the _old_ balances (i.e., it did not exist yet)
        // then say its balance was zero.
        let old_balance = old_balances
            .balances
            .get(val_index)
            .copied()
            .unwrap_or_else(|| 0);

        // If the validators vote is not known in the _new_ balances, then use a balance of zero.
        //
        // It is possible that there is a vote for an unknown validator if we change our justified
        // state to a new state with a higher epoch that is on a different fork (that fork may have
        // on-boarded less validators than the prior fork).
        let new_balance = new_balances
            .balances
            .get(val_index)
            .copied()
            .unwrap_or_else(|| 0);

        if vote.current_root != vote.next_root || old_balance != new_balance {
            *score_changes.entry(vote.current_root).or_insert(0) -= old_balance as i64;
            *score_changes.entry(vote.next_root).or_insert(0) += new_balance as i64;
            vote.current_root = vote.next_root;
        }
    }

    Ok(score_changes)
}

pub struct DagNode {
    root: Hash256,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    parent: Option<Hash256>,
}

pub struct ScoreChange {
    target: Hash256,
    score_delta: i64,
}

#[derive(Clone, Copy)]
pub struct Epochs {
    justified: Epoch,
    finalized: Epoch,
}

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
    pub fn is_better_then(&self, other: &Self) -> bool {
        if self.weight == other.weight {
            self.root > other.root
        } else {
            self.weight > other.weight
        }
    }
}

pub struct ProtoArray {
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
        changes: &[ScoreChange],
        justified_epoch: Epoch,
    ) -> Result<(), Error> {
        let mut deltas = produce_deltas(&self.indices, changes, self.nodes.len())?;

        self.ffg_update_required = justified_epoch != self.justified_epoch;
        if self.ffg_update_required {
            self.justified_epoch = self.justified_epoch;
        }

        for node_index in (0..self.nodes.len()).rev() {
            let node_delta = deltas
                .get(node_index)
                .copied()
                .ok_or_else(|| Error::InvalidNodeDelta(node_index))?;

            self.nodes
                .get_mut(node_index)
                .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                .weight
                .checked_add(node_delta as u64)
                .ok_or_else(|| Error::DeltaOverflow(node_index))?;

            if let Some(parent_index) = self
                .nodes
                .get(node_index)
                .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                .parent
            {
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
                    // for FFG changes, then check to see if the child is the best child for the
                    // parent. If so, remove the best-child link.
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

                let node_is_new_best_child = if let Some(parent_best_child_index) = self
                    .nodes
                    .get(parent_index)
                    .ok_or_else(|| Error::InvalidParentIndex(parent_index))?
                    .best_child
                {
                    let parent_best_child = self
                        .nodes
                        .get(parent_best_child_index)
                        .ok_or_else(|| Error::InvalidBestChildIndex(parent_best_child_index))?;

                    self.nodes
                        .get(node_index)
                        .ok_or_else(|| Error::InvalidNodeIndex(node_index))?
                        .is_better_then(parent_best_child)
                } else {
                    true
                };

                if node_is_new_best_child {
                    self.set_best_child(parent_index, node_index)?;
                }
            }
        }

        self.ffg_update_required = false;

        Ok(())
    }

    pub fn on_new_block(&mut self, block: DagNode) -> Result<(), Error> {
        let node_index = self.nodes.len();

        let node = ProtoNode {
            root: block.root,
            parent: block
                .parent
                .and_then(|parent_root| self.indices.get(&parent_root).copied()),
            justified_epoch: block.justified_epoch,
            finalized_epoch: block.finalized_epoch,
            weight: 0,
            best_child: None,
            best_descendant: None,
        };

        if let Some(parent_index) = node.parent {
            let parent = self
                .nodes
                .get(parent_index)
                .ok_or_else(|| Error::InvalidParentIndex(parent_index))?;

            let node_is_best_child = if let Some(parent_best_child_index) = parent.best_child {
                let parent_best_child = self
                    .nodes
                    .get(parent_best_child_index)
                    .ok_or_else(|| Error::InvalidBestChildIndex(parent_best_child_index))?;

                node.is_better_then(parent_best_child)
            } else {
                true
            };

            if node_is_best_child {
                self.set_best_child(parent_index, node_index)?;
            }
        }

        self.nodes.push(node);

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

/// Takes a list of `ScoreChange`, returning a list of deltas.
///
/// The returned list has the length of `num_nodes`. Each `ScoreChanged` is mapped to a position in
/// the returned list according to a lookup in `indices`.
///
/// ## Errors
///
/// It is an error to have a value in `indices` that is greater than or equal to `num_nodes`.
fn produce_deltas(
    indices: &HashMap<Hash256, usize>,
    changes: &[ScoreChange],
    num_nodes: usize,
) -> Result<Vec<i64>, Error> {
    let mut deltas: Vec<i64> = vec![0; num_nodes];

    // Update `deltas` with the value of each `ScoreChange`.
    changes.iter().try_for_each(|c| {
        let i = indices
            .get(&c.target)
            .ok_or_else(|| Error::NodeUnknown(c.target))?;

        let v = deltas.get_mut(*i).ok_or_else(|| Error::IndexOutOfBounds)?;
        v.saturating_add(c.score_delta);

        Ok(())
    })?;

    Ok(deltas)
}

/*
pub struct ProtoArray {
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    finalized_root: Hash256,
    /// Maps the index of some parent node to the index of its best-weighted child.
    best_child: Vec<Option<usize>>, // TODO: non-zero usize?
    /// Maps the index of some node to it's weight.
    weights: Vec<u64>,
    /// Maps the index of a node to the index of its parent.
    parents: Vec<Option<usize>>, // TODO: non-zero usize with +1 offset?
    /// Maps the index of a node to its finalized and justified epochs.
    epochs: Vec<Epochs>,
    /// Maps the index of a node to the index of its best-weighted descendant.
    best_descendant: Vec<usize>, // TODO: do I understand this correctly?
    // TODO: a `DagNode` stores epochs when we don't need them here.
    roots: Vec<Hash256>,
    indices: HashMap<Hash256, usize>,
}

impl ProtoArray {
    fn get_parent(&self, i: usize) -> Result<Option<usize>, Error> {
        self.parents
            .get(i)
            .copied()
            .ok_or_else(|| Error::ParentOutOfBounds {
                i,
                len: self.parents.len(),
            })
    }

    fn get_best_child(&self, i: usize) -> Result<Option<usize>, Error> {
        self.best_child
            .get(i)
            .copied()
            .ok_or_else(|| Error::BestChildOutOfBounds {
                i,
                len: self.best_child.len(),
            })
    }

    fn get_best_child_mut(&mut self, i: usize) -> Result<&mut Option<usize>, Error> {
        let len = self.best_child.len();
        self.best_child
            .get_mut(i)
            .ok_or_else(|| Error::BestChildOutOfBounds { i, len })
    }

    pub fn apply_score_changes(&mut self, changes: Vec<ScoreChange>) -> Result<(), Error> {
        // Check to ensure that the length of all internal arrays is consistent.
        self.check_consistency()?;

        let mut d: Vec<i64> = vec![0; self.roots.len()];

        let start = *self
            .indices
            .get(&self.finalized_root)
            .ok_or_else(|| Error::FinalizedNodeUnknown(self.finalized_root))?;

        // Provides safety for later calls in this function.
        if start >= d.len() {
            return Err(Error::StartOutOfBounds);
        }

        changes.iter().try_for_each(|c| {
            let i = self
                .indices
                .get(&c.target)
                .ok_or_else(|| Error::NodeUnknown(c.target))?;
            let v = d.get_mut(*i).ok_or_else(|| Error::IndexOutOfBounds)?;

            v.saturating_add(c.score_delta);

            Ok(())
        })?;

        // Back-prop diff values
        //
        // `start` is guaranteed to be greater than or equal to `d.len()` due to a previous check.
        for child in (start..d.len()).rev() {
            if let Some(parent) = self.get_parent(child)? {
                // There is no need to update the weight of the root node because its weight is
                // irrelevent.
                if parent > 0 {
                    // TODO: array access safety.
                    d[parent] += d[child]
                }
            }
        }

        // Apply diffs to weights
        for (i, delta) in d.iter().enumerate() {
            if *delta > 0 {
                // TODO: array access safety
                self.weights[i].saturating_add(*delta as u64)
            } else {
                // TODO: array access safety
                self.weights[i].saturating_sub(*delta as u64)
            };
        }

        // back-prop best-child/target updates
        for i in (start..d.len()).rev() {
            // TODO: is this a viable way to build the best descendant?
            if let Some(best_child) = self.get_best_child(i)? {
                // TODO: array access safety
                self.best_descendant[i] = self.best_descendant[best_child]
            }

            if d[i] == 0 {
                continue;
            }

            if let Some(parent) = self.get_parent(i)? {
                if let Some(best_child_of_parent) = self.get_best_child(parent)? {
                    // TODO: does it suffice to compare the deltas?
                    // TODO: what about tie breaking via hash?
                    // TODO: array access safety
                    if best_child_of_parent != i && d[i] >= d[best_child_of_parent] {
                        // TODO: array access safety
                        if self.weights[i] > self.weights[best_child_of_parent] {
                            self.best_child[parent] = Some(i)
                        }
                    }
                } else {
                    // TODO: what is this?
                    // TODO: array access safety
                    self.best_child[parent] = Some(i)
                }
            }
        }

        Ok(())
    }

    pub fn on_new_node(&mut self, block: DagNode) -> Result<(), Error> {
        let i = self.roots.len();
        self.indices.insert(block.root, i);

        // A new node does not have a best child (or any child at all).
        self.best_child.push(None);
        // A new node has weight 0.
        self.weights.push(0);
        // TODO: how can a new node not have a parent? Maybe the root node.
        if let Some(parent) = block.parent {
            if let Some(parent_index) = self.indices.get(&parent).copied() {
                self.parents.push(Some(parent_index));

                // TODO: don't set best child unless the fin/just states match.
                // If it is the first child, it is also the best.
                let best_child_of_parent = self.get_best_child_mut(parent_index)?;
                if best_child_of_parent.is_none() {
                    *best_child_of_parent = Some(i)
                }
            } else {
                // It is possible that the parent of this block is out-of-bounds (i.e.,
                // pre-finalizaton). In this case we simply ignore the parent.
                self.parents.push(None)
            }
        } else {
            self.parents.push(None)
        }

        self.epochs.push(Epochs {
            justified: block.justified_epoch,
            finalized: block.finalized_epoch,
        });
        // The new node points to itself as best-descendant, since it is a leaf.
        self.best_descendant.push(i);
        self.roots.push(block.root);

        Ok(())
    }

    fn maybe_prune(&mut self) -> Result<(), Error> {
        let start = *self
            .indices
            .get(&self.finalized_root)
            .ok_or_else(|| Error::FinalizedNodeUnknown(self.finalized_root))?;

        // Small pruning does not help more than it costs to do.
        if start < PRUNE_THRESHOLD {
            return Ok(());
        }

        self.best_child = self.best_child.split_off(start);
        self.weights = self.weights.split_off(start);
        self.parents = self.parents.split_off(start);
        self.best_descendant = self.best_descendant.split_off(start);

        for i in 0..start {
            // TODO: safe array access.
            let key = self.roots[i];
            self.indices.remove(&key);
        }

        self.roots = self.roots.split_off(start);

        // Adjust indices back to zero
        for (i, root) in self.roots.iter().enumerate() {
            // TODO: safe array access.
            if let Some(best_child) = self.best_child[i] {
                best_child.saturating_sub(start);
            }

            // TODO: safe array access.
            self.best_descendant[i].saturating_sub(start);

            self.parents[i] = if let Some(parent) = self.parents[i] {
                if parent < start {
                    None
                } else {
                    Some(parent.saturating_sub(start))
                }
            } else {
                None
            };

            *self
                .indices
                .get_mut(&root)
                .ok_or_else(|| Error::NodeUnknown(*root))? -= start
        }

        Ok(())
    }

    pub fn head_fn(&self, justified_root: &Hash256) -> Result<Hash256, Error> {
        let mut i = *self
            .indices
            .get(justified_root)
            .ok_or_else(|| Error::JustifiedNodeUnknown(self.finalized_root))?;

        loop {
            // TODO: safe array access.
            if let Some(best_child) = self.best_child[i] {
                i = best_child;
            } else {
                break;
            }
        }

        // TODO: safe array access.
        Ok(self.roots[i])
    }

    fn update_ffg(
        &mut self,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
    ) -> Result<(), Error> {
        if finalized_epoch == self.finalized_epoch && self.finalized_root != finalized_root {
            return Err(Error::InvalidFinalizedRootChange);
        }

        if finalized_epoch < self.finalized_epoch {
            return Err(Error::RevertedFinalizedEpoch);
        }

        let finalized_changed = self.finalized_epoch != finalized_epoch;
        let justified_changed = self.justified_epoch != justified_epoch;

        self.justified_epoch = justified_epoch;
        self.finalized_epoch = finalized_epoch;
        self.finalized_root = finalized_root;

        if finalized_changed {
            self.maybe_prune()?;
        }

        if justified_changed || finalized_changed {
            for (i, node_epochs) in self.epochs.iter().copied().enumerate().rev() {
                if node_epochs.justified == self.justified_epoch
                    && node_epochs.finalized == self.finalized_epoch
                {
                    continue;
                }

                if let Some(parent) = self.get_parent(i)? {
                    if let Some(parent_best_child) = self.get_best_child(parent)? {
                        if parent_best_child == i {
                            self.best_child[parent] = None
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_consistency(&self) -> Result<(), Error> {
        let num_nodes = self.roots.len();
        if self.best_child.len() != num_nodes {
            return Err(Error::BestChildInconsistent);
        }
        if self.weights.len() != num_nodes {
            return Err(Error::WeightsInconsistent);
        }
        if self.parents.len() != num_nodes {
            return Err(Error::ParentsInconsistent);
        }
        if self.best_descendant.len() != num_nodes {
            return Err(Error::BestDescendantInconsistent);
        }

        Ok(())
    }
}
*/

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

    pub fn exists(&self, i: usize) -> bool {
        i < self.0.len()
    }

    pub fn get(&mut self, i: usize) -> &T {
        self.ensure(i);
        &self.0[i]
    }

    pub fn get_ref(&self, i: usize) -> Option<&T> {
        self.0.get(i)
    }

    pub fn get_mut(&mut self, i: usize) -> &mut T {
        self.ensure(i);
        &mut self.0[i]
    }

    pub fn insert(&mut self, i: usize, element: T) {
        self.ensure(i);
        self.0[i] = element;
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }
}
