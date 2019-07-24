use super::MerkleTreeOverlay;
use crate::error::{Error, Result};
use crate::field::{Composite, Leaf, Node, Primitive};
use crate::tree_arithmetic::zeroed::{left_most_leaf, right_most_leaf, subtree_index_to_general};
use crate::tree_arithmetic::{log_base_two, next_power_of_two};
use crate::{NodeIndex, Path, BYTES_PER_CHUNK};
use ethereum_types::U256;
use ssz_types::{FixedVector, VariableList};
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

            fn get_node(path: Vec<Path>) -> Result<Node> {
                if path.len() == 0 {
                    Ok(Node::Leaf(Leaf::Primitive(vec![Primitive {
                        ident: "".to_owned(),
                        index: 0,
                        size: ($bit_size / 32) as u8,
                        offset: 0,
                    }])))
                } else {
                    Err(Error::InvalidPath(path[0].clone()))
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

/// Implements the `MerkleTreeOverlay` trait for SSZ Vector and List types.
///
/// The full specification of the merkle tree structure can be found in the SSZ documentation:
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/simple-serialize.md#merkleization
///
/// Below is a visual representation of the merkle tree for variable length Lists:
///
///             root
///           /      \
///      data_root   len
///        /   \
///       *     *           <= intermediate nodes
///      / \   / \
///     x   x x   x         <= leaf nodes
///
/// And a visual representation of the merkle tree for fixed length Vectors:
///
///             root(0)
///             /     \
///            *       *    <= intermediate nodes
///           / \     / \
///          x   x   x   x  <= leaf nodes

macro_rules! impl_merkle_overlay_for_collection_type {
    ($type: ident, $is_variable_length: expr) => {
        impl<T: MerkleTreeOverlay, N: Unsigned> MerkleTreeOverlay for $type<T, N> {
            fn height() -> u8 {
                let items_per_chunk = (BYTES_PER_CHUNK / std::mem::size_of::<T>()) as u64;
                let num_leaves = next_power_of_two(N::to_u64() / items_per_chunk);
                let data_tree_height = log_base_two(num_leaves) as u8;

                if $is_variable_length {
                    // Add one to account for the data root and the length of the list.
                    data_tree_height + 1
                } else {
                    data_tree_height
                }
            }

            fn first_leaf() -> NodeIndex {
                left_most_leaf(0, Self::height() as u64)
            }

            fn last_leaf() -> NodeIndex {
                if $is_variable_length {
                    // The last leaf in the data tree would be the right most leaf in the subtree
                    // rooted at 1, because the subtree rooted at 2 only defines the length of the
                    // structure and all of its children are unattached.
                    subtree_index_to_general(1, right_most_leaf(0, (Self::height() - 1) as u64))
                } else {
                    right_most_leaf(0, Self::height() as u64)
                }
            }

            fn get_node(path: Vec<Path>) -> Result<Node> {
                match path.first() {
                    // If the first element of the path is an index, it should exactly match the
                    // index of one of the leaf nodes in the current tree.
                    Some(Path::Index(position)) => {
                        // If the position in the collection is greater than the max number of
                        // elements, return an error.
                        if *position >= N::to_u64() {
                            return Err(Error::IndexOutOfBounds(*position));
                        }

                        let items_per_chunk = (BYTES_PER_CHUNK / std::mem::size_of::<T>()) as u64;
                        let leaf_index = Self::first_leaf() + (position / items_per_chunk);

                        // If the path terminates here, return the node in the current tree.
                        if path.len() == 1 {
                            Ok(generate_leaf::<Self, T>(leaf_index))

                        // If the path does not terminate, recursively call the child `T` to
                        // continue matching the path. Translate the child's return index to
                        // the current general index space.
                        } else {
                            let node = T::get_node(path[1..].to_vec())?;
                            let index = subtree_index_to_general(leaf_index, node.get_index());

                            Ok(replace_index(node.clone(), index))
                        }
                    }
                    // The only possible match for idents in a collection is when the collection is
                    // of dynamic length and the ident == "len". Otherwise, it is invalid.
                    Some(Path::Ident(i)) => {
                        if $is_variable_length && i == "len" {
                            Ok(Node::Leaf(Leaf::Length(Primitive {
                                ident: "len".to_string(),
                                index: 2,
                                size: 32,
                                offset: 0,
                            })))
                        } else {
                            Err(Error::InvalidPath(path[0].clone()))
                        }
                    }
                    // If there is no first element, return an error.
                    None => Err(Error::EmptyPath()),
                }
            }
        }
    };
}

impl_merkle_overlay_for_collection_type!(VariableList, true);
impl_merkle_overlay_for_collection_type!(FixedVector, false);

fn generate_leaf<S: MerkleTreeOverlay, T: MerkleTreeOverlay>(index: NodeIndex) -> Node {
    let node_type = T::get_node(vec![]);
    match node_type {
        Ok(_) => {
            let item_size = std::mem::size_of::<T>() as u8;
            let items_per_chunk = BYTES_PER_CHUNK as u8 / item_size;

            let values = vec![Primitive::default(); items_per_chunk as usize]
                .iter()
                .enumerate()
                .map(|(i, _)| Primitive {
                    ident: ((index - S::first_leaf()) * items_per_chunk as u64 + i as u64)
                        .to_string(),
                    index: index,
                    size: item_size,
                    offset: i as u8 * item_size,
                })
                .collect();

            Node::Leaf(Leaf::Primitive(values))
        }
        Err(_) => Node::Composite(Composite {
            ident: (index - S::first_leaf()).to_string(),
            index,
            height: T::height(),
        }),
    }
}

/// Returns a copy of `node` with all its index values changed to `index`.
pub fn replace_index(node: Node, index: NodeIndex) -> Node {
    match node {
        Node::Composite(c) => Node::Composite(Composite {
            ident: c.ident,
            index: index,
            height: c.height,
        }),
        Node::Leaf(Leaf::Primitive(b)) => Node::Leaf(Leaf::Primitive(
            b.iter()
                .cloned()
                .map(|mut x| {
                    x.index = index;
                    x
                })
                .collect(),
        )),
        Node::Leaf(Leaf::Length(b)) => Node::Leaf(Leaf::Length(Primitive {
            ident: b.ident,
            index: index,
            size: 32,
            offset: 0,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::{U1, U16, U2, U32, U4, U8};

    fn build_node(ident: &str, index: u64) -> Node {
        Node::Leaf(Leaf::Primitive(vec![Primitive {
            ident: ident.to_string(),
            index: index,
            size: 32,
            offset: 0,
        }]))
    }

    fn ident_path(ident: &str) -> Vec<Path> {
        vec![Path::Ident(ident.to_string())]
    }

    fn index_path(index: u64) -> Vec<Path> {
        vec![Path::Index(index)]
    }

    #[test]
    fn variable_list_overlay() {
        // Merkle structure for `VariableList<U256, U8>`
        //
        //                 +---------- 0 ----------+                 <= composite
        //                /           -+            \
        //          +--- 1 ---+        |        +--- 2 ---+          <= length
        //         /           \       |       /           \
        //        3             4      |- I   5             6        -+
        //      /   \         /   \    |    /   \         /   \       |
        //     7     8       9    10   |   11   12       13   14      |- unattacted
        //    / \   / \     / \   / \ -+  / \   / \     / \   / \     |
        //   15 16 17 18   19 20 21 22   23 24 25 26   27 28 29 30   -+
        //  |________________________|
        //              +
        //              |
        //              +--------------- leaves
        type T = VariableList<U256, U8>;

        // TESTING LENGTH NODE
        let node = Node::Leaf(Leaf::Length(Primitive {
            ident: "len".to_string(),
            index: 2,
            size: 32,
            offset: 0,
        }));

        assert_eq!(T::get_node(ident_path("len")), Ok(node.clone()));

        // TESTING LEAF NODES
        // position 0
        assert_eq!(T::get_node(index_path(0)), Ok(build_node("0", 15)));

        // position 3
        assert_eq!(T::get_node(index_path(3)), Ok(build_node("3", 18)));

        // position 7
        assert_eq!(T::get_node(index_path(7)), Ok(build_node("7", 22)));

        // TESTING OUT-OF-BOUNDS INDEX
        assert_eq!(T::get_node(index_path(9)), Err(Error::IndexOutOfBounds(9)));
    }

    #[test]
    fn nested_variable_list_overlay() {
        type T = VariableList<VariableList<VariableList<U256, U2>, U2>, U4>;

        // TESTING LENGTH NODE
        let node = Node::Leaf(Leaf::Length(Primitive {
            ident: "len".to_string(),
            index: 2,
            size: 32,
            offset: 0,
        }));

        // Testing root list length
        assert_eq!(
            T::get_node(vec![Path::Ident("len".to_string())]),
            Ok(node.clone())
        );

        // Testing list length for position 0
        let node = Node::Leaf(Leaf::Length(Primitive {
            ident: "len".to_string(),
            index: 16,
            size: 32,
            offset: 0,
        }));
        assert_eq!(
            T::get_node(vec![Path::Index(0), Path::Ident("len".to_string())]),
            Ok(node.clone())
        );

        // Testing list length for position 3
        let node = Node::Leaf(Leaf::Length(Primitive {
            ident: "len".to_string(),
            index: 22,
            size: 32,
            offset: 0,
        }));
        assert_eq!(
            T::get_node(vec![Path::Index(3), Path::Ident("len".to_string())]),
            Ok(node.clone())
        );

        // TESTING LEAF NODES
        // Node 131
        assert_eq!(
            T::get_node(vec![Path::Index(0), Path::Index(1), Path::Index(0)]),
            Ok(build_node("0", 131))
        );

        // Node 163
        assert_eq!(
            T::get_node(vec![Path::Index(2), Path::Index(1), Path::Index(0)]),
            Ok(build_node("0", 163))
        );

        // Node 176
        assert_eq!(
            T::get_node(vec![Path::Index(3), Path::Index(0), Path::Index(1)]),
            Ok(build_node("1", 176))
        );

        // TESTING OUT-OF-BOUNDS
        assert_eq!(
            T::get_node(vec![Path::Index(4)]),
            Err(Error::IndexOutOfBounds(4))
        );
        assert_eq!(
            T::get_node(vec![Path::Index(3), Path::Index(2)]),
            Err(Error::IndexOutOfBounds(2))
        );
        assert_eq!(
            T::get_node(vec![Path::Index(3), Path::Index(1), Path::Index(2)]),
            Err(Error::IndexOutOfBounds(2))
        );
    }

    #[test]
    fn simple_fixed_vector() {
        type T = FixedVector<U256, U8>;

        // Merkle structure for `FixedVector<U256, U8>`
        //
        //            ___ 0 ___              <= composite
        //           /         \            -+
        //          1           2            |
        //        /   \       /   \          |- intermediate
        //       3     4     5     6         |
        //      / \   / \   / \   / \       -+
        //     7   8 9  10 11 12 13 14      <= leaf

        assert_eq!(T::height(), 3);
        assert_eq!(T::first_leaf(), 7);
        assert_eq!(T::last_leaf(), 14);

        for i in 7..=14 {
            assert_eq!(
                T::get_node(vec![Path::Index(i - 7)]),
                Ok(build_node(&(i - 7).to_string(), i))
            );
        }

        // TESTING OUT-OF-BOUNDS
        assert_eq!(
            T::get_node(vec![Path::Index(8)]),
            Err(Error::IndexOutOfBounds(8))
        );

        // TESTING LENGTH
        assert_eq!(
            T::get_node(ident_path("len")),
            Err(Error::InvalidPath(Path::Ident("len".to_string())))
        );
    }

    #[test]
    fn another_simple_fixed_vector() {
        type T = FixedVector<u8, U32>;

        assert_eq!(T::height(), 0);
        assert_eq!(T::first_leaf(), 0);
        assert_eq!(T::last_leaf(), 0);

        // Generate root node
        let node = Node::Leaf(Leaf::Primitive(
            vec![Primitive::default(); 32]
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, mut p)| {
                    p.ident = i.to_string();
                    p.index = 0;
                    p.size = 1;
                    p.offset = i as u8;
                    p
                })
                .collect(),
        ));

        // TESTING ALL PATHS
        for i in 0..32 {
            assert_eq!(T::get_node(vec![Path::Index(i)]), Ok(node.clone()));
        }
    }

    #[test]
    fn nested_fixed_vector() {
        type T = FixedVector<FixedVector<FixedVector<U256, U16>, U2>, U1>;

        // Merkle structure for `FixedVector<FixedVector<FixedVector<U256, U2>, U2>, U1>`
        //
        //                           +-------------------- 0 --------------------+                             <= composite
        //                          /                                             \
        //               +-------- 1 --------+                           +-------- 2 --------+                 <= composite
        //              /                     \                         /                     \
        //         +-- 3 --+               +-- 4 --+               +-- 5 --+               +-- 6 --+           <= intermediate
        //        /         \             /         \             /         \             /         \
        //       7           8           9          10           11         12           13         14         <= intermediate
        //     /   \       /   \       /   \       /   \       /   \       /   \       /   \       /   \
        //    15   16     17   18     19   20     21   22     23   24     25   26     27   28     29   30      <= intermediate
        //   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \
        //  31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62    <= leaves

        assert_eq!(T::height(), 0);
        assert_eq!(T::first_leaf(), 0);
        assert_eq!(T::last_leaf(), 0);
    }
}
