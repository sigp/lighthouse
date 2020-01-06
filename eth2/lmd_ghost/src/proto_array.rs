use std::collections::HashMap;
use types::Hash256;

pub const PRUNE_THRESHOLD: usize = 200;

pub struct DagNode {
    block_root: Hash256,
    parent: Option<Hash256>,
}

pub struct Dag {
    finalized: Hash256,
}

pub struct ScoreChange {
    target: Hash256,
    score_delta: i64,
}

pub struct ProtoArray {
    dag: Dag,
    /// Maps the index of some parent node to the index of its best-weighted child.
    best_child: Vec<Option<usize>>, // TODO: non-zero usize?
    /// Maps the index of some node to it's weight.
    weights: Vec<u64>,
    /// Maps the index of a node to the index of its parent.
    parents: Vec<Option<usize>>, // TODO: non-zero usize with +1 offset?
    /// Maps the index of a node to the index of its best-weighted descendant.
    best_descendant: Vec<usize>, // TODO: do I understand this correctly?
    nodes: Vec<DagNode>,
    indices: HashMap<Hash256, usize>,
}

pub enum Error {
    NodeUnknown(Hash256),
    FinalizedNodeUnknown(Hash256),
    StartOutOfBounds,
    IndexOutOfBounds,
    BestChildOutOfBounds { i: usize, len: usize },
    ParentOutOfBounds { i: usize, len: usize },
    BestChildInconsistent,
    WeightsInconsistent,
    ParentsInconsistent,
    BestDescendantInconsistent,
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

    pub fn apply_score_changes(mut self, changes: Vec<ScoreChange>) -> Result<(), Error> {
        // Check to ensure that the length of all internal arrays is consistent.
        self.check_consistency()?;

        let mut d: Vec<i64> = vec![0; self.nodes.len()];

        let start = *self
            .indices
            .get(&self.dag.finalized)
            .ok_or_else(|| Error::FinalizedNodeUnknown(self.dag.finalized))?;

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

        for i in (start..d.len()).rev() {
            if let Some(best_child) = self.get_best_child(i)? {
                // TODO: array access safety
                self.best_descendant[i] = self.best_descendant[best_child]
            }

            if d[i] == 0 {
                continue;
            }

            if let Some(parent) = self.get_parent(i)? {
                if let Some(best_child_of_parent) = self.get_best_child(parent)? {
                    // TODO: does it suffice to just check the deltas?
                    // TODO: array access safety
                    if best_child_of_parent != i && d[i] >= d[best_child_of_parent] {
                        // TODO: array access safety
                        if self.weights[i] > self.weights[best_child_of_parent] {
                            self.best_child[parent] = Some(i)
                        }
                        // Do thing
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
        let i = self.nodes.len();
        self.indices.insert(block.block_root, i);

        // A new node does not have a best child (or any child at all).
        self.best_child.push(None);
        // A new node has weight 0.
        self.weights.push(0);
        // TODO: how can a new node not have a parent? Maybe the root node.
        if let Some(parent) = block.parent {
            if let Some(parent_index) = self.indices.get(&parent).copied() {
                self.parents.push(Some(parent_index));

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

        // The new node points to itself as best-descendant, since it is a leaf.
        self.best_descendant.push(i);
        self.nodes.push(block);

        Ok(())
    }

    pub fn prune(&mut self) -> Result<(), Error> {
        let start = *self
            .indices
            .get(&self.dag.finalized)
            .ok_or_else(|| Error::FinalizedNodeUnknown(self.dag.finalized))?;

        // Small pruning does not help more than it costs to do.
        if start < 200 {
            return Ok(());
        }

        self.best_child = self.best_child.split_off(start);
        self.weights = self.weights.split_off(start);
        self.parents = self.parents.split_off(start);
        self.best_descendant = self.best_descendant.split_off(start);

        for i in 0..start {
            // TODO: safe array access.
            let key = self.nodes[i].block_root;
            self.indices.remove(&key);
        }

        self.nodes = self.nodes.split_off(start);

        // Adjust indices back to zero
        for (i, node) in self.nodes.iter().enumerate() {
            // TODO: safe array access.
            if let Some(best_child) = self.best_child[i] {
                best_child.saturating_sub(start);
            }

            // TODO: safe array access.
            self.best_descendant[i].saturating_sub(start);

            if let Some(parent) = self.parents[i] {
                if parent < start {
                    parent = None
                } else {
                    // TODO: what happens if this becomes negative?? Safety issue.
                    parent -= start
                }
            }

            self.indices
                .get_mut(n.block_root)
                .ok_or_else(|| Error::NodeUnknown(n.block_root))? -= start
        }

        Ok(())
    }

    fn check_consistency(&self) -> Result<(), Error> {
        let num_nodes = self.nodes.len();
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
