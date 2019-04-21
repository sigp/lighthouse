use super::*;

#[derive(Debug, PartialEq, Clone)]
pub struct BTreeOverlay {
    pub offset: usize,
    pub num_items: usize,
    pub lengths: Vec<usize>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize) -> Result<Self, Error>
    where
        T: CachedTreeHashSubTree<T>,
    {
        item.tree_hash_cache_overlay(initial_offset)
    }

    pub fn from_lengths(
        offset: usize,
        num_items: usize,
        lengths: Vec<usize>,
    ) -> Result<Self, Error> {
        if lengths.is_empty() {
            Err(Error::TreeCannotHaveZeroNodes)
        } else {
            Ok(Self {
                offset,
                num_items,
                lengths,
            })
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
        self.first_node() + self.num_internal_nodes() + self.num_leaf_nodes() - self.lengths.len()
            + self.lengths.iter().sum::<usize>()
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

#[cfg(test)]
mod test {
    use super::*;

    fn get_tree_a(n: usize) -> BTreeOverlay {
        BTreeOverlay::from_lengths(0, n, vec![1; n]).unwrap()
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

        let tree = BTreeOverlay::from_lengths(11, 4, vec![1, 1]).unwrap();
        assert_eq!(tree.chunk_range(), 11..14);
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
