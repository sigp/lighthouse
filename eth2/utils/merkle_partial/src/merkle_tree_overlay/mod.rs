pub mod impls;

use crate::error::Result;
use crate::field::Node;
use crate::{NodeIndex, Path};

pub trait MerkleTreeOverlay {
    /// Returns the `Node` coresponding to the `path`.
    ///
    /// This will match path[0] against a field in the current object and recusively call itself
    /// on that field's type with path[1..] until the path is exhausted.
    ///
    /// See the SSZ specification to better understand the tree architecture:
    /// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md
    /// Returns the `Node` coresponding to the given `path`.
    fn get_node(path: Vec<Path>) -> Result<Node>;

    /// Returns the height of the merkle tree.
    fn height() -> u8;

    /// Returns the index of the first leaf in the merkle tree.
    fn first_leaf() -> NodeIndex;

    /// Returns the index of the last leaf in the merkle tree.
    fn last_leaf() -> NodeIndex;
}
