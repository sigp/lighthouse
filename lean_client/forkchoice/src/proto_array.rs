use lean_consensus::attestation::Slot;
use std::collections::HashMap;
use types::{FixedBytesExtended, Hash256};

/// Errors returned by [`ProtoArray`].
#[derive(Debug, PartialEq, Eq)]
pub enum ProtoArrayError {
    /// Attempted to register a block whose parent is unknown.
    UnknownParent {
        block_root: Hash256,
        parent_root: Hash256,
    },
    /// Attempted to update or query an unknown block root.
    UnknownBlock(Hash256),
    /// Attempted to access an invalid node index.
    InvalidNodeIndex(usize),
}

/// Execution status of a node in the proto-array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Unknown,
    Valid,
    Invalid,
}

/// Node metadata tracked by the proto-array.
#[derive(Debug, Clone)]
struct ProtoNode {
    slot: Slot,
    root: Hash256,
    parent: Option<usize>,
    children: Vec<usize>,
    weight: i64,
    best_child: Option<usize>,
    best_descendant: Option<usize>,
    execution_status: ExecutionStatus,
}

impl ProtoNode {
    fn new(slot: Slot, root: Hash256, parent: Option<usize>) -> Self {
        Self {
            slot,
            root,
            parent,
            children: Vec::new(),
            weight: 0,
            best_child: None,
            best_descendant: None,
            execution_status: ExecutionStatus::Unknown,
        }
    }
}

/// Proto-array implementation that mirrors the spec's fork-choice structure.
///
/// Tracks parent/child relationships, cumulative weights, best-child/best-descendant metadata,
/// and execution payload validity. Weight updates are propagated to ancestors so fork choice
/// can walk the heaviest subtree starting from a justified root.
#[derive(Debug, Default)]
pub struct ProtoArray {
    nodes: Vec<ProtoNode>,
    indices: HashMap<Hash256, usize>,
}

impl ProtoArray {
    /// Create a proto-array initialized with the genesis block.
    pub fn new(genesis_root: Hash256, genesis_slot: Slot) -> Self {
        let mut indices = HashMap::new();
        indices.insert(genesis_root, 0);

        Self {
            nodes: vec![ProtoNode::new(genesis_slot, genesis_root, None)],
            indices,
        }
    }

    /// Returns `true` if the proto array already contains `root`.
    pub fn contains(&self, root: &Hash256) -> bool {
        self.indices.contains_key(root)
    }

    fn node_index(&self, root: &Hash256) -> Result<usize, ProtoArrayError> {
        self.indices
            .get(root)
            .copied()
            .ok_or_else(|| ProtoArrayError::UnknownBlock(*root))
    }

    /// Registers a new block in the proto array.
    pub fn on_block(
        &mut self,
        block_root: Hash256,
        block_slot: Slot,
        parent_root: Hash256,
    ) -> Result<(), ProtoArrayError> {
        if self.contains(&block_root) {
            return Ok(());
        }

        let parent_index =
            if parent_root == Hash256::zero() {
                None
            } else {
                Some(self.indices.get(&parent_root).copied().ok_or(
                    ProtoArrayError::UnknownParent {
                        block_root,
                        parent_root,
                    },
                )?)
            };

        let node_index = self.nodes.len();
        let node = ProtoNode::new(block_slot, block_root, parent_index);

        if let Some(parent_idx) = parent_index {
            self.nodes[parent_idx].children.push(node_index);
        }

        self.indices.insert(block_root, node_index);
        self.nodes.push(node);

        // Update metadata for this node and its ancestors.
        self.update_best_paths(node_index)?;
        let mut current = parent_index;
        while let Some(idx) = current {
            self.update_best_paths(idx)?;
            current = self.nodes[idx].parent;
        }

        Ok(())
    }

    /// Adds `weight` to `block_root` and all of its ancestors.
    pub fn add_weight(&mut self, block_root: Hash256, weight: u64) -> Result<(), ProtoArrayError> {
        self.apply_weight_delta(block_root, weight as i64)
    }

    /// Removes `weight` from `block_root` and its ancestors, saturating at zero.
    pub fn remove_weight(
        &mut self,
        block_root: Hash256,
        weight: u64,
    ) -> Result<(), ProtoArrayError> {
        self.apply_weight_delta(block_root, -(weight as i64))
    }

    /// Returns the canonical head when starting at `start_root`.
    ///
    /// Traversal selects the child whose subtree has the highest weight. Ties fall back to the
    /// highest slot, then lexicographically greatest root for stability.
    pub fn find_head(&self, start_root: Hash256) -> Result<Hash256, ProtoArrayError> {
        let mut index = self.node_index(&start_root)?;

        loop {
            let node = self
                .nodes
                .get(index)
                .ok_or_else(|| ProtoArrayError::UnknownBlock(start_root))?;

            let best_child_idx = match node.best_child {
                Some(idx) => idx,
                None => return Ok(node.root),
            };

            let next = self.nodes[best_child_idx]
                .best_descendant
                .unwrap_or(best_child_idx);
            index = next;
        }
    }

    /// Returns the total number of tracked nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the proto array is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Marks a block as having a valid execution payload.
    pub fn mark_execution_valid(&mut self, block_root: Hash256) -> Result<(), ProtoArrayError> {
        let index = self.node_index(&block_root)?;
        self.nodes[index].execution_status = ExecutionStatus::Valid;
        Ok(())
    }

    /// Marks a block as having an invalid execution payload.
    pub fn mark_execution_invalid(&mut self, block_root: Hash256) -> Result<(), ProtoArrayError> {
        let index = self.node_index(&block_root)?;
        self.nodes[index].execution_status = ExecutionStatus::Invalid;
        Ok(())
    }

    fn apply_weight_delta(
        &mut self,
        block_root: Hash256,
        delta: i64,
    ) -> Result<(), ProtoArrayError> {
        let mut index = self.node_index(&block_root)?;

        loop {
            let node = self
                .nodes
                .get_mut(index)
                .ok_or(ProtoArrayError::InvalidNodeIndex(index))?;

            node.weight = (node.weight + delta).max(0);

            let _ = node;
            self.update_best_paths(index)?;

            match self.nodes[index].parent {
                Some(parent_index) => index = parent_index,
                None => break,
            }
        }

        Ok(())
    }

    fn update_best_paths(&mut self, index: usize) -> Result<(), ProtoArrayError> {
        let (best_child, best_descendant) = self.compute_best_paths(index)?;

        let node = self
            .nodes
            .get_mut(index)
            .ok_or(ProtoArrayError::InvalidNodeIndex(index))?;
        node.best_child = best_child;
        node.best_descendant = best_descendant;
        Ok(())
    }

    fn compute_best_paths(
        &self,
        index: usize,
    ) -> Result<(Option<usize>, Option<usize>), ProtoArrayError> {
        let node = self
            .nodes
            .get(index)
            .ok_or(ProtoArrayError::InvalidNodeIndex(index))?;

        let mut best_child: Option<usize> = None;
        let mut best_descendant: Option<usize> = None;

        for &child_idx in &node.children {
            let child = self
                .nodes
                .get(child_idx)
                .ok_or(ProtoArrayError::InvalidNodeIndex(child_idx))?;
            if child.execution_status == ExecutionStatus::Invalid {
                continue;
            }

            let candidate_idx = child.best_descendant.unwrap_or(child_idx);
            let candidate = self
                .nodes
                .get(candidate_idx)
                .ok_or(ProtoArrayError::InvalidNodeIndex(candidate_idx))?;
            if candidate.execution_status == ExecutionStatus::Invalid {
                continue;
            }

            match best_child {
                None => {
                    best_child = Some(child_idx);
                    best_descendant = Some(candidate_idx);
                }
                Some(current_child_idx) => {
                    let current_candidate_idx = best_descendant.unwrap_or(current_child_idx);
                    let current_candidate = self
                        .nodes
                        .get(current_candidate_idx)
                        .ok_or(ProtoArrayError::InvalidNodeIndex(current_candidate_idx))?;
                    let current_key = (
                        self.nodes[current_child_idx].weight,
                        current_candidate.slot.0,
                        current_candidate.root,
                    );

                    let candidate_key = (
                        self.nodes[child_idx].weight,
                        candidate.slot.0,
                        candidate.root,
                    );

                    if candidate_key > current_key {
                        best_child = Some(child_idx);
                        best_descendant = Some(candidate_idx);
                    }
                }
            }
        }

        Ok((best_child, best_descendant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(i: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        Hash256::from(bytes)
    }

    #[test]
    fn can_register_blocks() {
        let genesis = hash(0);
        let mut proto_array = ProtoArray::new(genesis, Slot(0));
        assert_eq!(proto_array.len(), 1);

        let child = hash(1);
        proto_array
            .on_block(child, Slot(1), genesis)
            .expect("child added");
        assert!(proto_array.contains(&child));
        assert_eq!(proto_array.len(), 2);
    }

    #[test]
    fn rejects_unknown_parent() {
        let genesis = hash(0);
        let mut proto_array = ProtoArray::new(genesis, Slot(0));

        let err = proto_array
            .on_block(hash(2), Slot(1), hash(1))
            .expect_err("missing parent");

        assert_eq!(
            err,
            ProtoArrayError::UnknownParent {
                block_root: hash(2),
                parent_root: hash(1)
            }
        );
    }

    #[test]
    fn weight_updates_affect_ancestors() {
        let genesis = hash(0);
        let mut proto_array = ProtoArray::new(genesis, Slot(0));
        let a = hash(1);
        let b = hash(2);

        proto_array
            .on_block(a, Slot(1), genesis)
            .expect("add block a");
        proto_array.on_block(b, Slot(2), a).expect("add block b");

        proto_array
            .add_weight(b, 2)
            .expect("weight applied to chain");

        let head = proto_array.find_head(genesis).expect("head");
        assert_eq!(head, b);
    }

    #[test]
    fn remove_weight_walks_parents() {
        let genesis = hash(0);
        let mut proto_array = ProtoArray::new(genesis, Slot(0));
        let a = hash(1);

        proto_array
            .on_block(a, Slot(1), genesis)
            .expect("add block a");
        proto_array.add_weight(a, 5).expect("weight");
        proto_array.remove_weight(a, 5).expect("remove weight");

        let head = proto_array.find_head(genesis).expect("head");
        assert_eq!(head, a, "head stays on last child when weights equal");
    }
}
