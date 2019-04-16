use super::*;

#[derive(Debug)]
pub struct BTreeOverlay {
    pub num_internal_nodes: usize,
    pub num_leaf_nodes: usize,
    pub first_node: usize,
    pub next_node: usize,
    offsets: Vec<usize>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize) -> Result<Self, Error>
    where
        T: CachedTreeHashSubTree<T>,
    {
        item.tree_hash_cache_overlay(initial_offset)
    }

    pub fn from_lengths(offset: usize, mut lengths: Vec<usize>) -> Result<Self, Error> {
        // Extend it to the next power-of-two, if it is not already.
        let num_leaf_nodes = if lengths.len().is_power_of_two() {
            lengths.len()
        } else {
            let num_leaf_nodes = lengths.len().next_power_of_two();
            lengths.resize(num_leaf_nodes, 1);
            num_leaf_nodes
        };

        let num_nodes = num_nodes(num_leaf_nodes);
        let num_internal_nodes = num_nodes - num_leaf_nodes;

        let mut offsets = Vec::with_capacity(num_nodes);
        offsets.append(&mut (offset..offset + num_internal_nodes).collect());

        let mut next_node = num_internal_nodes + offset;
        for i in 0..num_leaf_nodes {
            offsets.push(next_node);
            next_node += lengths[i];
        }

        Ok(Self {
            num_internal_nodes,
            num_leaf_nodes,
            offsets,
            first_node: offset,
            next_node,
        })
    }

    pub fn root(&self) -> usize {
        self.first_node
    }

    pub fn height(&self) -> usize {
        self.num_leaf_nodes.trailing_zeros() as usize
    }

    pub fn chunk_range(&self) -> Range<usize> {
        self.first_node..self.next_node
    }

    pub fn total_chunks(&self) -> usize {
        self.next_node - self.first_node
    }

    pub fn total_nodes(&self) -> usize {
        self.num_internal_nodes + self.num_leaf_nodes
    }

    pub fn first_leaf_node(&self) -> Result<usize, Error> {
        self.offsets
            .get(self.num_internal_nodes)
            .cloned()
            .ok_or_else(|| Error::NoFirstNode)
    }

    /// Returns an iterator visiting each internal node, providing the left and right child chunks
    /// for the node.
    pub fn iter_internal_nodes<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (&'a usize, (&'a usize, &'a usize))> {
        let internal_nodes = &self.offsets[0..self.num_internal_nodes];

        internal_nodes.iter().enumerate().map(move |(i, parent)| {
            let children = children(i);
            (
                parent,
                (&self.offsets[children.0], &self.offsets[children.1]),
            )
        })
    }

    /// Returns an iterator visiting each leaf node, providing the chunk for that node.
    pub fn iter_leaf_nodes<'a>(&'a self) -> impl DoubleEndedIterator<Item = &'a usize> {
        let leaf_nodes = &self.offsets[self.num_internal_nodes..];

        leaf_nodes.iter()
    }
}
