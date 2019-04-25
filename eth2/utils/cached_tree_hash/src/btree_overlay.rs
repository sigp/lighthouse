use super::*;

#[derive(Debug, PartialEq, Clone)]
pub struct BTreeOverlay {
    pub offset: usize,
    pub depth: usize,
    pub num_items: usize,
    pub lengths: Vec<usize>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize, depth: usize) -> Result<Self, Error>
    where
        T: CachedTreeHash<T>,
    {
        item.tree_hash_cache_overlay(initial_offset, depth)
    }

    pub fn from_lengths(
        offset: usize,
        num_items: usize,
        depth: usize,
        lengths: Vec<usize>,
    ) -> Result<Self, Error> {
        if lengths.is_empty() {
            Err(Error::TreeCannotHaveZeroNodes)
        } else {
            Ok(Self {
                offset,
                num_items,
                depth,
                lengths,
            })
        }
    }

    pub fn num_leaf_nodes(&self) -> usize {
        self.lengths.len().next_power_of_two()
    }

    pub fn num_padding_leaves(&self) -> usize {
        self.num_leaf_nodes() - self.lengths.len()
    }

    /// Returns the number of nodes in the tree.
    ///
    /// Note: this is distinct from `num_chunks`, which returns the total number of chunks in
    /// this tree.
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
        self.first_node() + self.num_internal_nodes() + self.num_leaf_nodes() - self.lengths.len()
            + self.lengths.iter().sum::<usize>()
    }

    pub fn height(&self) -> usize {
        self.num_leaf_nodes().trailing_zeros() as usize
    }

    pub fn chunk_range(&self) -> Range<usize> {
        self.first_node()..self.next_node()
    }

    /// Returns the number of chunks inside this tree (including subtrees).
    ///
    /// Note: this is distinct from `num_nodes` which returns the number of nodes in the binary
    /// tree.
    pub fn num_chunks(&self) -> usize {
        self.next_node() - self.first_node()
    }

    pub fn first_leaf_node(&self) -> usize {
        self.offset + self.num_internal_nodes()
    }

    /// Returns the chunk-range for a given leaf node.
    ///
    /// Returns `None` if:
    ///     - The specified node is internal.
    ///     - The specified node is padding.
    ///     - The specified node is OOB of the tree.
    pub fn get_leaf_node(&self, i: usize) -> Result<Option<Range<usize>>, Error> {
        if i >= self.num_nodes() - self.num_padding_leaves() {
            Ok(None)
        } else if (i == self.num_internal_nodes()) && (self.num_items == 0) {
            // If this is the first leaf node and the overlay contains zero items, return `None` as
            // this node must be padding.
            Ok(None)
        } else {
            let i = i - self.num_internal_nodes();

            let first_node = self.offset
                + self.num_internal_nodes()
                + self.lengths.iter().take(i).sum::<usize>();
            let last_node = first_node + self.lengths[i];

            Ok(Some(first_node..last_node))
        }
    }

    pub fn child_chunks(&self, parent: usize) -> (usize, usize) {
        let children = children(parent);

        if children.1 < self.num_internal_nodes() {
            (children.0 + self.offset, children.1 + self.offset)
        } else {
            let chunks = self.n_leaf_node_chunks(children.1);
            (chunks[chunks.len() - 2], chunks[chunks.len() - 1])
        }
    }

    /// (parent, (left_child, right_child))
    pub fn internal_parents_and_children(&self) -> Vec<(usize, (usize, usize))> {
        let mut chunks = Vec::with_capacity(self.num_nodes());
        chunks.append(&mut self.internal_node_chunks());
        chunks.append(&mut self.leaf_node_chunks());

        (0..self.num_internal_nodes())
            .into_iter()
            .map(|parent| {
                let children = children(parent);
                (chunks[parent], (chunks[children.0], chunks[children.1]))
            })
            .collect()
    }

    // Returns a `Vec` of chunk indices for each internal node of the tree.
    pub fn internal_node_chunks(&self) -> Vec<usize> {
        (self.offset..self.offset + self.num_internal_nodes()).collect()
    }

    // Returns a `Vec` of the first chunk index for each leaf node of the tree.
    pub fn leaf_node_chunks(&self) -> Vec<usize> {
        self.n_leaf_node_chunks(self.num_leaf_nodes())
    }

    // Returns a `Vec` of the first chunk index for the first `n` leaf nodes of the tree.
    fn n_leaf_node_chunks(&self, n: usize) -> Vec<usize> {
        let mut chunks = Vec::with_capacity(n);

        let mut chunk = self.offset + self.num_internal_nodes();
        for i in 0..n {
            chunks.push(chunk);

            match self.lengths.get(i) {
                Some(len) => {
                    chunk += len;
                }
                None => chunk += 1,
            }
        }

        chunks
    }
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

#[cfg(test)]
mod test {
    use super::*;

    fn get_tree_a(n: usize) -> BTreeOverlay {
        BTreeOverlay::from_lengths(0, n, 0, vec![1; n]).unwrap()
    }

    #[test]
    fn leaf_node_chunks() {
        let tree = get_tree_a(4);

        assert_eq!(tree.leaf_node_chunks(), vec![3, 4, 5, 6])
    }

    #[test]
    fn internal_node_chunks() {
        let tree = get_tree_a(4);

        assert_eq!(tree.internal_node_chunks(), vec![0, 1, 2])
    }

    #[test]
    fn internal_parents_and_children() {
        let tree = get_tree_a(4);

        assert_eq!(
            tree.internal_parents_and_children(),
            vec![(0, (1, 2)), (1, (3, 4)), (2, (5, 6))]
        )
    }

    #[test]
    fn chunk_range() {
        let tree = get_tree_a(4);
        assert_eq!(tree.chunk_range(), 0..7);

        let tree = get_tree_a(1);
        assert_eq!(tree.chunk_range(), 0..1);

        let tree = get_tree_a(2);
        assert_eq!(tree.chunk_range(), 0..3);

        let tree = BTreeOverlay::from_lengths(11, 4, 0, vec![1, 1]).unwrap();
        assert_eq!(tree.chunk_range(), 11..14);
    }

    #[test]
    fn get_leaf_node() {
        let tree = get_tree_a(4);

        assert_eq!(tree.get_leaf_node(3), Ok(Some(3..4)));
        assert_eq!(tree.get_leaf_node(4), Ok(Some(4..5)));
        assert_eq!(tree.get_leaf_node(5), Ok(Some(5..6)));
        assert_eq!(tree.get_leaf_node(6), Ok(Some(6..7)));
    }

    #[test]
    fn root_of_one_node() {
        let tree = get_tree_a(1);

        assert_eq!(tree.root(), 0);
        assert_eq!(tree.num_internal_nodes(), 0);
        assert_eq!(tree.num_leaf_nodes(), 1);
    }

    #[test]
    fn child_chunks() {
        let tree = get_tree_a(4);

        assert_eq!(tree.child_chunks(0), (1, 2))
    }
}
