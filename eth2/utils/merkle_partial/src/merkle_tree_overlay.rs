use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Basic, Composite, Leaf, Node};
use crate::path::Path;
use crate::tree_arithmetic::zeroed::{is_in_subtree, subtree_index_to_general};
use crate::vec_to_array;
use crate::{NodeIndex, BYTES_PER_CHUNK};

pub trait MerkleTreeOverlay {
    /// Returns the height of the struct (e.g. log(next_power_of_two(pack(self).len())))
    fn height(&self) -> u8;

    /// Gets the `Node` coresponding to the general index.
    fn get_node(&self, index: NodeIndex) -> Node;
}

pub fn match_path_element(
    item: &dyn MerkleTreeOverlay,
    cache: &Cache,
    path: Path,
    root: NodeIndex,
) -> Result<(NodeIndex, u8, u8)> {
    match path.clone() {
        Path::Ident(ident) => {
            for leaf in leaf_indices(item.height()) {
                match item.get_node(subtree_index_to_general(root, leaf)) {
                    Node::Leaf(Leaf::Basic(b)) => {
                        for field in b {
                            if field.ident == *ident {
                                return Ok((field.index, field.offset, field.size));
                            }
                        }
                    }
                    Node::Leaf(Leaf::Length(l)) => {
                        if l.ident == *ident {
                            return Ok((l.index, l.offset, l.size));
                        }
                    }
                    Node::Composite(_) => {
                        unimplemented!("Loading composite from path not supported")
                    }
                    _ => (),
                }
            }
        }
        Path::Index(i) => {
            let first_leaf = 2_u64.pow(item.height() as u32 - 1) - 1;

            if let Node::Leaf(Leaf::Basic(b)) =
                item.get_node(subtree_index_to_general(root, first_leaf))
            {
                if let Node::Leaf(Leaf::Length(Basic { index, .. })) =
                    item.get_node(subtree_index_to_general(root, 2))
                {
                    let length = u64::from_le_bytes(vec_to_array!(
                        cache.get(index).ok_or(Error::MissingNode(index))?,
                        8
                    ));

                    if i >= length {
                        return Err(Error::IndexOutOfBounds(i as usize));
                    }

                    let items_per_chunk = BYTES_PER_CHUNK as u8 / b[0].size;
                    let index = first_leaf + i / items_per_chunk as u64;

                    if let Node::Leaf(Leaf::Basic(b)) =
                        item.get_node(subtree_index_to_general(root, index))
                    {
                        return Ok((b[0].index, (i % items_per_chunk as u64) as u8, b[0].size));
                    }
                }
            }
        }
    }

    Err(Error::InvalidPath(path))
}

fn leaf_indices(height: u8) -> Vec<NodeIndex> {
    let mut ret: Vec<NodeIndex> = vec![];
    for i in 2_u64.pow(height as u32)..(2_u64.pow(height as u32 + 1) - 1) {
        ret.push(i - 1);
    }

    ret
}
// vector merkle tree
//
//        b_root(0)
//       /         \
// b_data_root(1) b_len(2)
//    /   \
//  . . . . .
//
impl<T> MerkleTreeOverlay for Vec<T> {
    /// Default vectors to the maximum capped length of 2**32
    fn height(&self) -> u8 {
        32_u8
    }

    /// Gets the `Node` coresponding to the general index.
    fn get_node(&self, index: NodeIndex) -> Node {
        if !is_in_subtree(1, index + 1) {
            panic!("");
        }

        const CAPPED_DEPTH: NodeIndex = 32;
        const FIRST_INTERNAL: NodeIndex = 3;
        const LAST_INTERNAL: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 2;
        const FIRST_LEAF: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 1;
        const LAST_LEAF: NodeIndex = (1_u64 << CAPPED_DEPTH) - 1;

        match index {
            0 => Node::Composite(Composite {
                ident: "",
                index: 0,
                height: self.height().into(),
            }),
            1 => Node::Intermediate(index),
            2 => Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: index,
                size: 32,
                offset: 0,
            })),
            FIRST_INTERNAL...LAST_INTERNAL => Node::Intermediate(index),
            FIRST_LEAF...LAST_LEAF => {
                let mut items: Vec<Basic> = vec![];

                let item_size = std::mem::size_of::<T>() as u8;
                let items_per_chunk = BYTES_PER_CHUNK as u8 / item_size;

                for i in 0..items_per_chunk {
                    let offset = i * item_size;

                    items.push(Basic {
                        ident: (((index + 1) % 2_u64.pow(CAPPED_DEPTH as u32 - 1))
                            * items_per_chunk as u64
                            + i as u64)
                            .to_string(),
                        index,
                        size: item_size as u8,
                        offset,
                    })
                }

                Node::Leaf(Leaf::Basic(items))
            }
            i => unreachable!("Node out of bounds: {}, last leaf: {}", i, LAST_LEAF),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::U256;

    #[test]
    fn vec_overlay() {
        let a: Vec<U256> = vec![];

        assert_eq!(
            a.get_node(2),
            Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: 2,
                size: 32,
                offset: 0
            }))
        );

        assert_eq!(
            a.get_node(2_u64.pow(31) - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 0.to_string(),
                index: 2_u64.pow(31) - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            a.get_node(2_u64.pow(31) + 1000 - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 1000.to_string(),
                index: 2_u64.pow(31) + 1000 - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            a.get_node(2 * (2_u64.pow(31) - 1)),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: (2_u64.pow(31) - 1).to_string(),
                index: 2 * (2_u64.pow(31) - 1),
                size: 32,
                offset: 0
            }]))
        );
    }
}
