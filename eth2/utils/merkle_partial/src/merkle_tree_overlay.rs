use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Basic, Composite, Leaf, Node};
use crate::path::Path;
use crate::tree_arithmetic::zeroed::{relative_depth, root_from_depth, subtree_index_to_general};
use crate::vec_to_array;
use crate::{NodeIndex, BYTES_PER_CHUNK};
use ethereum_types::U256;

pub trait MerkleTreeOverlay {
    /// Returns the height of the struct (e.g. log(next_power_of_two(pack(self).len())))
    fn height() -> u8;

    /// Gets the `Node` coresponding to the general index.
    fn get_node(index: NodeIndex) -> Node;
}

pub fn match_path_element<T: MerkleTreeOverlay>(
    cache: &Cache,
    path: Path,
    root: NodeIndex,
) -> Result<(NodeIndex, u8, u8)> {
    match path.clone() {
        Path::Ident(ident) => {
            for leaf in leaf_indices(T::height()) {
                match T::get_node(subtree_index_to_general(root, leaf)) {
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
            let first_leaf = 2_u64.pow(T::height() as u32 - 1) - 1;

            if let Node::Leaf(Leaf::Basic(b)) =
                T::get_node(subtree_index_to_general(root, first_leaf))
            {
                if let Node::Leaf(Leaf::Length(Basic { index, .. })) =
                    T::get_node(subtree_index_to_general(root, 2))
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
                        T::get_node(subtree_index_to_general(root, index))
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
impl<T: MerkleTreeOverlay> MerkleTreeOverlay for Vec<T> {
    /// Default vectors to the maximum capped length of 2**32
    fn height() -> u8 {
        32_u8
    }

    /// Gets the `Node` coresponding to the general index.
    fn get_node(index: NodeIndex) -> Node {
        const CAPPED_DEPTH: NodeIndex = 32;

        const FIRST_INTERNAL: NodeIndex = 3;
        const LAST_INTERNAL: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 2;

        const FIRST_LEAF: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 1;
        const LAST_LEAF: NodeIndex = (1_u64 << CAPPED_DEPTH) - 1;

        const FIRST_CHILD: NodeIndex = LAST_LEAF + 1;
        const LAST_CHILD: NodeIndex = std::u64::MAX;

        match index {
            0 => Node::Composite(Composite {
                ident: "",
                index: 0,
                height: Self::height().into(),
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
            FIRST_CHILD...LAST_CHILD => {
                let subtree_root = root_from_depth(index, relative_depth(FIRST_LEAF, index));

                if (FIRST_LEAF..=LAST_LEAF).contains(&subtree_root) {
                    T::get_node(index)
                } else {
                    Node::Unattached(index)
                }
            }
        }
    }
}

macro_rules! impl_merkle_overlay_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl MerkleTreeOverlay for $type {
            fn height() -> u8 {
                0
            }

            fn get_node(index: NodeIndex) -> Node {
                match index {
                    0 => Node::Leaf(Leaf::Basic(vec![Basic {
                        ident: "".to_string(),
                        index,
                        size: ($bit_size / 32) as u8,
                        offset: 0,
                    }])),
                    _ => Node::Unattached(index),
                }
            }
        }
    };
}

impl_merkle_overlay_for_uint!(u8, 8);
impl_merkle_overlay_for_uint!(u16, 16);
impl_merkle_overlay_for_uint!(u32, 32);
impl_merkle_overlay_for_uint!(u64, 64);
impl_merkle_overlay_for_uint!(u128, 128);
impl_merkle_overlay_for_uint!(U256, 256);
impl_merkle_overlay_for_uint!(bool, 8);
impl_merkle_overlay_for_uint!(usize, std::mem::size_of::<usize>());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_overlay() {
        assert_eq!(
            Vec::<U256>::get_node(0),
            Node::Composite(Composite {
                ident: "",
                index: 0,
                height: 32
            })
        );

        assert_eq!(Vec::<U256>::get_node(1), Node::Intermediate(1));
        assert_eq!(Vec::<U256>::get_node(100), Node::Intermediate(100));

        assert_eq!(
            Vec::<U256>::get_node(2),
            Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: 2,
                size: 32,
                offset: 0
            }))
        );

        assert_eq!(
            Vec::<U256>::get_node(2_u64.pow(31) - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 0.to_string(),
                index: 2_u64.pow(31) - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            Vec::<U256>::get_node(2_u64.pow(31) + 1000 - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 1000.to_string(),
                index: 2_u64.pow(31) + 1000 - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            Vec::<U256>::get_node(2 * (2_u64.pow(31) - 1)),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: (2_u64.pow(31) - 1).to_string(),
                index: 2 * (2_u64.pow(31) - 1),
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            Vec::<U256>::get_node(2_u64.pow(32)),
            Node::Unattached(2_u64.pow(32))
        );
    }
}
