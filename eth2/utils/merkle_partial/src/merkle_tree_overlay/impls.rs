use super::MerkleTreeOverlay;
use crate::field::{Basic, Composite, Leaf, Node};
use crate::tree_arithmetic::zeroed::{relative_depth, root_from_depth};
use crate::tree_arithmetic::{log_base_two, next_power_of_two};
use crate::{NodeIndex, BYTES_PER_CHUNK};
use ethereum_types::U256;
use ssz_types::VariableList;
use typenum::Unsigned;

macro_rules! impl_merkle_overlay_for_basic_type {
    ($type: ident, $bit_size: expr) => {
        impl MerkleTreeOverlay for $type {
            fn height() -> u8 {
                0
            }

            fn first_leaf() -> NodeIndex {
                0
            }

            fn last_leaf() -> NodeIndex {
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

impl_merkle_overlay_for_basic_type!(bool, 8);
impl_merkle_overlay_for_basic_type!(u8, 8);
impl_merkle_overlay_for_basic_type!(u16, 16);
impl_merkle_overlay_for_basic_type!(u32, 32);
impl_merkle_overlay_for_basic_type!(u64, 64);
impl_merkle_overlay_for_basic_type!(u128, 128);
impl_merkle_overlay_for_basic_type!(U256, 256);
impl_merkle_overlay_for_basic_type!(usize, std::mem::size_of::<usize>());

// VariableList merkle tree
//
//         root(0)
//       /         \
//  data_root(1) b_len(2)
//    /   \
//  . . . . .

impl<T: MerkleTreeOverlay, N: Unsigned> MerkleTreeOverlay for VariableList<T, N> {
    fn height() -> u8 {
        1 + log_base_two(next_power_of_two(N::to_u64())) as u8
    }

    fn first_leaf() -> NodeIndex {
        (1_u64 << Self::height()) - 1
    }

    fn last_leaf() -> NodeIndex {
        (1_u64 << Self::height()) + (1_u64 << Self::height()) / 2 - 2
    }

    fn get_node(index: NodeIndex) -> Node {
        let first_internal = 3;
        let last_internal = (1_u64 << Self::height()) - 2;

        let first_leaf = Self::first_leaf();
        let last_leaf = Self::last_leaf();

        if index == 0 {
            Node::Composite(Composite {
                ident: "",
                index: 0,
                height: Self::height().into(),
            })
        } else if index == 1 {
            Node::Intermediate(index)
        } else if index == 2 {
            Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: index,
                size: 32,
                offset: 0,
            }))
        } else if (first_internal..=last_internal).contains(&index) {
            Node::Intermediate(index)
        } else if (first_leaf..=last_leaf).contains(&index) {
            let mut items: Vec<Basic> = vec![];

            let item_size = std::mem::size_of::<T>() as u8;
            let items_per_chunk = BYTES_PER_CHUNK as u8 / item_size;

            for i in 0..items_per_chunk {
                let offset = i * item_size;

                items.push(Basic {
                    ident: (((index + 1) % 2_u64.pow(Self::height() as u32 - 1))
                        * items_per_chunk as u64
                        + i as u64)
                        .to_string(),
                    index,
                    size: item_size as u8,
                    offset,
                })
            }

            Node::Leaf(Leaf::Basic(items))
        } else {
            let subtree_root = root_from_depth(index, relative_depth(first_leaf, index));

            if (first_leaf..=last_leaf).contains(&subtree_root) {
                T::get_node(index)
            } else {
                Node::Unattached(index)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::U8;

    #[test]
    fn vec_overlay() {
        type T = VariableList<U256, U8>;
        assert_eq!(
            T::get_node(0),
            Node::Composite(Composite {
                ident: "",
                index: 0,
                height: T::height(),
            })
        );

        assert_eq!(T::get_node(1), Node::Intermediate(1));
        assert_eq!(T::get_node(10), Node::Intermediate(10));

        assert_eq!(
            T::get_node(2),
            Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: 2,
                size: 32,
                offset: 0
            }))
        );

        assert_eq!(
            T::get_node(15),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 0.to_string(),
                index: 15,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            T::get_node(18),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 3.to_string(),
                index: 18,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            T::get_node(22),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 7.to_string(),
                index: 22,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(T::get_node(23), Node::Unattached(23));
        assert_eq!(T::get_node(2_u64.pow(32)), Node::Unattached(2_u64.pow(32)));
    }
}
