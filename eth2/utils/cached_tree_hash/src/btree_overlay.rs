use super::*;

#[derive(Debug, PartialEq, Clone)]
pub struct BTreeSchema {
    pub depth: usize,
    lengths: Vec<usize>,
}

impl BTreeSchema {
    pub fn from_lengths(depth: usize, lengths: Vec<usize>) -> Self {
        Self { depth, lengths }
    }

    pub fn into_overlay(self, offset: usize) -> BTreeOverlay {
        BTreeOverlay::from_schema(self, offset)
    }
}

impl Into<BTreeSchema> for BTreeOverlay {
    fn into(self) -> BTreeSchema {
        BTreeSchema {
            depth: self.depth,
            lengths: self.lengths,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LeafNode {
    DoesNotExist,
    Exists(Range<usize>),
    Padding,
}

#[derive(Debug, PartialEq, Clone)]
pub struct BTreeOverlay {
    offset: usize,
    pub depth: usize,
    lengths: Vec<usize>,
    leaf_nodes: Vec<LeafNode>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize, depth: usize) -> Self
    where
        T: CachedTreeHash<T>,
    {
        Self::from_schema(item.tree_hash_cache_schema(depth), initial_offset)
    }

    pub fn from_schema(schema: BTreeSchema, offset: usize) -> Self {
        let num_leaf_nodes = schema.lengths.len().next_power_of_two();
        let num_internal_nodes = num_leaf_nodes - 1;

        let mut running_offset = offset + num_internal_nodes;
        let leaf_nodes: Vec<LeafNode> = schema
            .lengths
            .iter()
            .map(|length| {
                let range = running_offset..running_offset + length;
                running_offset += length;
                LeafNode::Exists(range)
            })
            .collect();

        Self {
            offset,
            depth: schema.depth,
            lengths: schema.lengths,
            leaf_nodes,
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

    pub fn internal_chunk_range(&self) -> Range<usize> {
        self.offset..self.offset + self.num_internal_nodes()
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
    pub fn get_leaf_node(&self, i: usize) -> Result<LeafNode, Error> {
        if i >= self.num_nodes() {
            Ok(LeafNode::DoesNotExist)
        } else if i >= self.num_nodes() - self.num_padding_leaves() {
            Ok(LeafNode::Padding)
        } else if (i == self.num_internal_nodes()) && (self.lengths.len() == 0) {
            // If this is the first leaf node and the overlay contains zero items, return `None` as
            // this node must be padding.
            Ok(LeafNode::Padding)
        } else {
            let i = i - self.num_internal_nodes();

            Ok(self.leaf_nodes[i].clone())
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
        BTreeSchema::from_lengths(0, vec![1; n]).into_overlay(0)
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

        let tree = BTreeSchema::from_lengths(0, vec![1, 1]).into_overlay(11);
        assert_eq!(tree.chunk_range(), 11..14);

        let tree = BTreeSchema::from_lengths(0, vec![7, 7, 7]).into_overlay(0);
        assert_eq!(tree.chunk_range(), 0..25);
    }

    #[test]
    fn get_leaf_node() {
        let tree = get_tree_a(4);

        assert_eq!(tree.get_leaf_node(3), Ok(LeafNode::Exists(3..4)));
        assert_eq!(tree.get_leaf_node(4), Ok(LeafNode::Exists(4..5)));
        assert_eq!(tree.get_leaf_node(5), Ok(LeafNode::Exists(5..6)));
        assert_eq!(tree.get_leaf_node(6), Ok(LeafNode::Exists(6..7)));
        assert_eq!(tree.get_leaf_node(7), Ok(LeafNode::DoesNotExist));

        let tree = get_tree_a(3);

        assert_eq!(tree.get_leaf_node(3), Ok(LeafNode::Exists(3..4)));
        assert_eq!(tree.get_leaf_node(4), Ok(LeafNode::Exists(4..5)));
        assert_eq!(tree.get_leaf_node(5), Ok(LeafNode::Exists(5..6)));
        assert_eq!(tree.get_leaf_node(6), Ok(LeafNode::Padding));
        assert_eq!(tree.get_leaf_node(7), Ok(LeafNode::DoesNotExist));

        let tree = get_tree_a(0);

        assert_eq!(tree.get_leaf_node(0), Ok(LeafNode::Padding));
        assert_eq!(tree.get_leaf_node(1), Ok(LeafNode::DoesNotExist));

        let tree = BTreeSchema::from_lengths(0, vec![3]).into_overlay(0);
        assert_eq!(tree.get_leaf_node(0), Ok(LeafNode::Exists(0..3)));
        assert_eq!(tree.get_leaf_node(1), Ok(LeafNode::DoesNotExist));

        let tree = BTreeSchema::from_lengths(0, vec![3]).into_overlay(10);
        assert_eq!(tree.get_leaf_node(0), Ok(LeafNode::Exists(10..13)));
        assert_eq!(tree.get_leaf_node(1), Ok(LeafNode::DoesNotExist));
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
