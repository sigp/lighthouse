use super::*;

#[derive(Debug, PartialEq, Clone)]
pub struct BTreeOverlay {
    pub offset: usize,
    lengths: Vec<usize>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize) -> Result<Self, Error>
    where
        T: CachedTreeHashSubTree<T>,
    {
        item.tree_hash_cache_overlay(initial_offset)
    }

    pub fn from_lengths(offset: usize, lengths: Vec<usize>) -> Result<Self, Error> {
        if lengths.is_empty() {
            Err(Error::TreeCannotHaveZeroNodes)
        } else {
            Ok(Self { offset, lengths })
        }
    }

    pub fn num_leaf_nodes(&self) -> usize {
        self.lengths.len().next_power_of_two()
    }

    fn num_padding_leaves(&self) -> usize {
        self.num_leaf_nodes() - self.lengths.len()
    }

    pub fn num_nodes(&self) -> usize {
        2 * self.num_leaf_nodes() - 1
    }

    pub fn num_internal_nodes(&self) -> usize {
        self.num_leaf_nodes() - 1
    }

    fn first_node(&self) -> usize {
        self.offset
    }

    pub fn root(&self) -> usize {
        self.first_node()
    }

    pub fn next_node(&self) -> usize {
        self.first_node() + self.lengths.iter().sum::<usize>()
    }

    pub fn height(&self) -> usize {
        self.num_leaf_nodes().trailing_zeros() as usize
    }

    pub fn chunk_range(&self) -> Range<usize> {
        self.first_node()..self.next_node()
    }

    pub fn total_chunks(&self) -> usize {
        self.next_node() - self.first_node()
    }

    pub fn first_leaf_node(&self) -> usize {
        self.offset + self.num_internal_nodes()
    }

    pub fn get_leaf_node(&self, i: usize) -> Result<Option<Range<usize>>, Error> {
        if i >= self.num_leaf_nodes() {
            return Err(Error::NotLeafNode(i));
        } else if i >= self.num_leaf_nodes() - self.num_padding_leaves() {
            Ok(None)
        } else {
            let first_node = self.offset + self.lengths.iter().take(i).sum::<usize>();
            let last_node = first_node + self.lengths[i];
            Ok(Some(first_node..last_node))
        }
    }

    /// Returns an iterator visiting each internal node, providing the left and right child chunks
    /// for the node.
    pub fn internal_parents_and_children(&self) -> Vec<(usize, (usize, usize))> {
        (0..self.num_internal_nodes())
            .into_iter()
            .map(|parent| {
                let children = children(parent);
                (
                    parent + self.offset,
                    (children.0 + self.offset, children.1 + self.offset),
                )
            })
            .collect()
    }

    // Returns a `Vec` of chunk indices for each internal node of the tree.
    pub fn internal_node_chunks(&self) -> Vec<usize> {
        (self.offset..self.offset + self.num_internal_nodes()).collect()
    }
}
