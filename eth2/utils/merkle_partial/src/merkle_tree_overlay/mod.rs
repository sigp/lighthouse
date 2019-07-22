pub mod impls;
pub mod path_matcher;

use crate::error::Result;
use crate::field::Node;
use crate::{NodeIndex, Path};

pub trait MerkleTreeOverlay {
    /// Returns the height of the merkle tree.
    fn height() -> u8;

    /// Returns the `Node` coresponding to the general index `index` in the merkle tree.
    ///
    /// There are four main branches to be taken when matching an index to the
    /// coresponding node.
    ///
    /// 1. Root: The 0 index will always match to the root node in the tree and will return a
    ///   `Composite` node type that reflects attributes of the current object.
    /// 2. Internal: Nodes in the `1..first_leaf` are considered internal (except for
    ///    the edge case state in the comment above) to the tree and always hold a
    ///    intermediate chunk.
    /// 3. Leaf: When the index matches a node in the `first_leaf..=last_leaf` range
    ///    exactly, it will return the coresponding `Composite` node or list of
    ///    `Primitive` nodes.
    /// 4. Child: A child node lives below the leaves of the current tree. It may be a
    ///    part of child object, or it may be unattached to any tree. These indexes
    ///    should call recursively into the root object of the subtree in which the
    ///    child index resides.
    ///
    /// See the SSZ specification to better understand the tree architecture:
    /// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md
    fn get_node(index: NodeIndex) -> Node;

    fn get_node_from_path(path: Vec<Path>) -> Result<Node>;

    /// Returns the index of the first leaf in the merkle tree.
    fn first_leaf() -> NodeIndex;

    /// Returns the index of the last leaf in the merkle tree.
    fn last_leaf() -> NodeIndex;
}
