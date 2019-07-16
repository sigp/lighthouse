pub mod impls;
pub mod path_matcher;

use crate::field::Node;
use crate::NodeIndex;

pub trait MerkleTreeOverlay {
    /// Returns the height of the merkle tree.
    fn height() -> u8;

    /// Returns the `Node` coresponding to the general index `index` in the merkle tree.
    fn get_node(index: NodeIndex) -> Node;

    /// Returns the index of the first leaf in the merkle tree.
    fn first_leaf() -> NodeIndex;

    /// Returns the index of the last leaf in the merkle tree.
    fn last_leaf() -> NodeIndex;
}
