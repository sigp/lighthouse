use super::MerkleTreeOverlay;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use crate::path::Path;
use crate::tree_arithmetic::zeroed::subtree_index_to_general;
use crate::NodeIndex;

pub fn match_path<T: MerkleTreeOverlay>(
    path: Path,
    root: NodeIndex,
    height: u8,
) -> Result<(NodeIndex, u8, u8, u8)> {
    let leaves = match path.clone() {
        Path::Ident(_) => vec![0; 1_usize << height]
            .iter()
            .enumerate()
            .map(|(i, _)| {
                T::get_node(subtree_index_to_general(
                    root,
                    compute_first_leaf(height) + i as u64,
                ))
            })
            .collect(),
        Path::Index(i) => vec![T::get_node(compute_first_leaf(height) + i)],
    };

    for leaf in leaves {
        match leaf {
            Node::Leaf(Leaf::Basic(chunk_fields)) => {
                for field in chunk_fields {
                    if path.to_string() == field.ident {
                        return Ok((field.index, 0, field.offset, field.size));
                    }
                }
            }
            Node::Composite(field) => {
                if path.to_string() == field.ident {
                    return Ok((field.index, field.height, 0, 32));
                }
            }
            _ => (),
        }
    }

    Err(Error::InvalidPath(path))
}

/// Helper function to calculate the first leaf for an object of `height`.
fn compute_first_leaf(height: u8) -> NodeIndex {
    (1_u64 << height) - 1
}
