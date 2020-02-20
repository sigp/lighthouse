use crate::{get_zero_hash, Hash256};
use eth2_hashing::{Context, Digest, SHA256};
use std::mem;
use std::num::NonZeroUsize;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The maximum number of leaves defined by the initialization `depth` has been exceed.
    MaximumLeavesExceeded { max_leaves: usize },
}

/// Helper struct to store either a hash digest or a slice.
///
/// Should be used as a left or right value for some node.
enum Preimage<'a> {
    Digest(Digest),
    Slice(&'a [u8]),
}

impl<'a> Preimage<'a> {
    /// Returns a 32-byte slice.
    fn as_bytes(&self) -> &[u8] {
        match self {
            Preimage::Digest(digest) => digest.as_ref(),
            Preimage::Slice(slice) => slice,
        }
    }
}

/// A node that has had a left child supplied, but not a right child.
struct HalfNode {
    /// The hasher context.
    context: Context,
    /// The tree id of the node. The root node has in id of `1` and ids increase moving down the
    /// tree from left to right.
    id: usize,
}

impl HalfNode {
    /// Create a new half-node from the given `left` value.
    fn new(id: usize, left: Preimage) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(left.as_bytes());

        Self { context, id }
    }

    /// Complete the half-node by providing a `right` value. Returns a digest of the left and right
    /// nodes.
    fn finish(mut self, right: Preimage) -> Digest {
        self.context.update(right.as_bytes());
        self.context.finish()
    }
}

/// Provides a Merkle-root hasher that allows for streaming leaves (viz., providing them
/// one-by-one) and also for efficiently handling the cases where not all leaves have been
/// provided (by assuming all non-provided leaves are `[0; 32]` and pre-computing the zero-value
/// hashes at all depths of the tree).
///
/// This algorithm aims to allocate as little memory as possible and it does this by "folding" up
/// the tree has each leaf is provided. Consider this step-by-step functional diagram of hashing a
/// tree with height three:
///
/// ## Functional Diagram
///
/// Nodes that are `-` have not been defined and do not occupy memory. Nodes that are `L` are
/// leaves that are provided but are not stored. Nodes that have integers (`1`, `2`) are stored in
/// our struct. Finally, nodes that are `X` were stored, but are now removed.
///
/// ### Start
///
/// ```ignore
///           -
///          / \
///         -   -
///        / \ / \
///       -  - -  -
/// ```
///
/// ### Provide first leaf
///
/// ```ignore
///           -
///          / \
///         2   -
///        / \ / \
///       L  - -  -
/// ```
///
/// ### Provide second leaf
///
/// ```ignore
///           1
///          / \
///         X   -
///        / \ / \
///       L  L -  -
/// ```
///
/// ### Provide third leaf
///
/// ```ignore
///           1
///          / \
///         X   3
///        / \ / \
///       L  L L  -
/// ```
///
/// ### Provide fourth and final leaf
///
/// ```ignore
///           1
///          / \
///         X   X
///        / \ / \
///       L  L L  L
/// ```
///
struct MerkleStream {
    // TODO: smallvec.
    half_nodes: Vec<HalfNode>,
    depth: usize,
    next_leaf: usize,
    root: Option<Hash256>,
}

/// Returns the parent of node with id `i`.
fn get_parent(i: usize) -> usize {
    i / 2
}

/// Gets the depth of a node with an id of `i`.
///
/// It is a logic error to provide `i == 0`.
///
/// E.g., if `i` is 1, depth is 0. If `i` is is 1, depth is 1.
fn get_depth(i: usize) -> usize {
    let total_bits = mem::size_of::<usize>() * 8;
    total_bits - i.leading_zeros() as usize - 1
}

impl MerkleStream {
    /// Instantiates a new, empty hasher for a tree with `depth` layers which will have capacity
    /// for `1 << (depth - 1)` leaf nodes.
    ///
    /// It is not possible to grow the depth of the tree after instantiation.
    pub fn new(depth: NonZeroUsize) -> Self {
        let depth = depth.get();

        Self {
            half_nodes: vec![],
            depth,
            next_leaf: 1 << (depth - 1),
            root: None,
        }
    }

    /// Process the next leaf in the tree.
    ///
    /// ## Errors
    ///
    /// Returns an error if the given leaf would exceed the maximum permissible number of leaves
    /// defined by the initialization `depth`. E.g., a tree of `depth == 2` can only accept 2
    /// leaves. A tree of `depth == 14` can only accept 8,192 leaves.
    pub fn process_leaf(&mut self, leaf: &Hash256) -> Result<(), Error> {
        let max_leaves = 1 << (self.depth + 1);

        if self.next_leaf > max_leaves {
            return Err(Error::MaximumLeavesExceeded { max_leaves });
        } else if self.next_leaf == 1 {
            // A tree of height one has a root that is equal to the first given leaf.
            self.root = Some(*leaf)
        } else if self.next_leaf % 2 == 0 {
            self.process_left_node(self.next_leaf, Preimage::Slice(leaf.as_bytes()))
        } else {
            self.process_right_node(self.next_leaf, Preimage::Slice(leaf.as_bytes()))
        }

        self.next_leaf += 1;

        Ok(())
    }

    /// Returns the root of the Merkle tree.
    ///
    /// If not all leaves have been provided, the tree will be efficiently completed under the
    /// assumption that all not-yet-provided leaves are equal to `[0; 32]`.
    pub fn finish(mut self) -> Hash256 {
        // If the tree is incomplete, we must complete it by providing zero-hashes.
        loop {
            if let Some(root) = self.root {
                break root;
            } else {
                if let Some(node) = self.half_nodes.last() {
                    let right_child = node.id * 2 + 1;
                    self.process_right_node(right_child, self.zero_hash(right_child));
                } else if self.next_leaf == 1 {
                    // The next_leaf can only be 1 if the tree has a height of one. If have been no
                    // leaves supplied, assume a root of zero.
                    break Hash256::zero();
                } else {
                    // The only scenario where there are (a) no half nodes and (b) a tree of height
                    // two or more is where no leaves have been supplied at all.
                    //
                    // Once we supply this first zero-hash leaf then all future operations will be
                    // triggered via the `process_right_node` branch.
                    self.process_left_node(self.next_leaf, self.zero_hash(self.next_leaf))
                }
            }
        }
    }

    /// Process a node that will become the left-hand node of some parent. The supplied `id` is
    /// that of the node (not the parent). The `preimage` is the value of the node (i.e., if this
    /// is a leaf node it will be the value of that leaf).
    ///
    /// In this scenario, the only option is to push a new half-node.
    fn process_left_node(&mut self, id: usize, preimage: Preimage) {
        self.half_nodes
            .push(HalfNode::new(get_parent(id), preimage))
    }

    /// Process a node that will become the right-hand node of some parent. The supplied `id` is
    /// that of the node (not the parent). The `preimage` is the value of the node (i.e., if this
    /// is a leaf node it will be the value of that leaf).
    ///
    /// This operation will always complete one node, then it will attempt to crawl up the tree and
    /// collapse and other viable nodes. For example, consider a tree of height 3 (see diagram
    /// below). When providing the node with id `7`, the node with id `3` will be completed which
    /// will also provide the right-node for the `1` node. This function will complete both of
    /// those nodes and ultimately find the root of the tree.
    ///
    /// ```ignore
    ///           1 <-- completed
    ///          / \
    ///         2   3  <-- completed
    ///        / \ / \
    ///       4  5 6  7 <-- supplied right node
    /// ```
    fn process_right_node(&mut self, id: usize, mut preimage: Preimage) {
        println!("right {}", id);
        let mut parent = get_parent(id);

        loop {
            match self.half_nodes.last() {
                Some(node) if node.id == parent => {
                    preimage = Preimage::Digest(
                        self.half_nodes
                            .pop()
                            .expect("if .last() is Some then .pop() must succeed")
                            .finish(preimage),
                    );
                    if parent == 1 {
                        self.root = Some(Hash256::from_slice(preimage.as_bytes()));
                        break;
                    } else {
                        parent = get_parent(parent);
                    }
                }
                _ => {
                    self.half_nodes.push(HalfNode::new(parent, preimage));
                    break;
                }
            }
        }
    }

    /// Returns a "zero hash" from a pre-computed set for the given node.
    ///
    /// Note: this node is not always zero, instead it is the result of hashing up a tree where the
    /// leaves are all zeros.  E.g., in a tree of depth 2, the `zero_hash` of a node at depth 1
    /// will be `[0; 32]`.  However, the `zero_hash` for a node at depth 0 will be
    /// `hash(concat([0; 32], [0; 32])))`.
    fn zero_hash(&self, id: usize) -> Preimage<'static> {
        Preimage::Slice(get_zero_hash(self.depth - (get_depth(id) + 1)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkleize_padded;

    fn do_test(leaves: &[Hash256], depth: usize) {
        let reference_bytes = leaves
            .iter()
            .map(|hash| hash.as_bytes().to_vec())
            .flatten()
            .collect::<Vec<_>>();

        let reference_root = merkleize_padded(&reference_bytes, 1 << (depth - 1));
        let merklizer_root = {
            let mut m =
                MerkleStream::new(NonZeroUsize::new(depth).expect("depth should not be zero"));
            for leaf in leaves.iter() {
                m.process_leaf(leaf).expect("should process leaf");
            }
            m.finish()
        };

        assert_eq!(
            reference_root, merklizer_root,
            "should match reference root"
        );
    }

    fn with_len(leaves: u64, height: usize) {
        let leaves = (0..leaves)
            .map(|i| Hash256::from_low_u64_be(i))
            .collect::<Vec<_>>();
        do_test(&leaves, height)
    }

    #[test]
    fn height() {
        assert_eq!(get_depth(1), 0);
        assert_eq!(get_depth(2), 1);
        assert_eq!(get_depth(3), 1);
        assert_eq!(get_depth(4), 2);
        assert_eq!(get_depth(5), 2);
        assert_eq!(get_depth(6), 2);
        assert_eq!(get_depth(7), 2);
        assert_eq!(get_depth(8), 3);
    }

    #[test]
    #[should_panic]
    fn too_many_leaves() {
        with_len(2, 1);
    }

    #[test]
    fn full_trees() {
        with_len(1, 1);
        with_len(2, 2);
        with_len(4, 3);
        with_len(8, 4);
        with_len(16, 5);
        with_len(32, 6);
        with_len(64, 7);
        with_len(128, 8);
        with_len(256, 9);
        with_len(256, 9);
        with_len(8192, 14);
    }

    #[test]
    fn incomplete_trees() {
        with_len(0, 1);

        with_len(0, 2);
        with_len(1, 2);

        for i in 0..=4 {
            with_len(i, 3);
        }

        for i in 0..=7 {
            with_len(i, 4);
        }

        for i in 0..=15 {
            with_len(i, 5);
        }

        for i in 0..=32 {
            with_len(i, 6);
        }

        for i in 0..=64 {
            with_len(i, 7);
        }

        with_len(0, 14);
        with_len(13, 14);
        with_len(8191, 14);
    }
}
