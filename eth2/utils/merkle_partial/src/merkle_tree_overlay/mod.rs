pub mod impls;
pub mod path_matcher;

use crate::field::Node;
use crate::NodeIndex;

pub trait MerkleTreeOverlay {
    /// Returns the height of the struct (e.g. log(next_power_of_two(num_leaves)))
    fn height() -> u8;

    /// Gets the `Node` coresponding to the general index.
    fn get_node(index: NodeIndex) -> Node;

    /// todo
    fn first_leaf() -> NodeIndex;

    /// todo
    fn last_leaf() -> NodeIndex;
}
