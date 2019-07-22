use super::MerkleTreeOverlay;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use crate::path::Path;
use crate::tree_arithmetic::zeroed::subtree_index_to_general;
use crate::NodeIndex;

/// Find the `index`, `height`, `offset`, and `size` of node matching `path` for the type `T`.
pub fn match_path<T: MerkleTreeOverlay + ?Sized>(
    path: Path,
    root: NodeIndex,
    height: u8,
) -> Result<(NodeIndex, u8, u8, u8)> {
    // If the path is an `Index` type then the coresponding node can be directly calculated, but
    // for `Ident` paths the only way to locate the field is loop through every leaf.
    let leaves: Vec<Node> = match path.clone() {
        Path::Ident(_) => vec![0; 1_usize << T::height()]
            .iter()
            .enumerate()
            .map(|(i, _)| {
                T::get_node(subtree_index_to_general(
                    root,
                    compute_first_leaf(height) + i as u64,
                ))
            })
            .collect(),

        // There could be a performance improvement by storing the size of array elements for the
        // `Composite` and using them to compute the exact leaf the index is refering to.
        Path::Index(index) => vec![0; (compute_first_leaf(height) + index) as usize]
            .iter()
            .enumerate()
            .map(|(i, _)| {
                T::get_node(subtree_index_to_general(
                    root,
                    compute_first_leaf(height) + i as u64,
                ))
            })
            .collect(),
    };

    println!("leaves: {:?}", leaves);

    for leaf in leaves {
        match leaf {
            Node::Leaf(Leaf::Primitive(chunk_fields)) => {
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
