use crate::field::{Basic, Composite, Leaf, Node};
use crate::tree_arithmetic::{general_index_to_subtree, is_in_subtree};
use crate::{NodeIndex, BYTES_PER_CHUNK};

pub trait MerkleTreeOverlay {
    /// Returns the height of the struct (e.g. log(next_power_of_two(pack(self).len())))
    fn height(&self) -> usize;

    /// Gets the `Node` coresponding to the general index.
    fn get_node(&self, root: NodeIndex, index: NodeIndex) -> Node;
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
    fn height(&self) -> usize {
        32
    }

    /// Gets the `Node` coresponding to the general index.
    fn get_node(&self, root: NodeIndex, index: NodeIndex) -> Node {
        if !is_in_subtree(root + 1, index + 1) {
            panic!("");
        }

        const CAPPED_DEPTH: NodeIndex = 32;
        const FIRST_INTERNAL: NodeIndex = 3;
        const LAST_INTERNAL: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 2;
        const FIRST_LEAF: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 1;
        const LAST_LEAF: NodeIndex = (1_u64 << CAPPED_DEPTH) - 1;

        // Function in one indexed, so perfrom +/- transformations
        let local_index = general_index_to_subtree(root + 1, index + 1) - 1;

        match local_index {
            0 => Node::Composite(Composite {
                ident: "",
                index: 0,
                height: self.height(),
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
                let size = std::mem::size_of::<T>();
                let items_per_chunk: u64 = (BYTES_PER_CHUNK / size) as u64;

                let mut items: Vec<Basic> = vec![];

                for i in 0..items_per_chunk {
                    let offset = (i * size as u64) as u8;

                    items.push(Basic {
                        ident: (((local_index + 1) % 2_u64.pow(CAPPED_DEPTH as u32 - 1))
                            * items_per_chunk
                            + i)
                            .to_string(),
                        index,
                        size,
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
            a.get_node(0, 2),
            Node::Leaf(Leaf::Length(Basic {
                ident: "len".to_string(),
                index: 2,
                size: 32,
                offset: 0
            }))
        );

        assert_eq!(
            a.get_node(0, 2_u64.pow(31) - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 0.to_string(),
                index: 2_u64.pow(31) - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            a.get_node(0, 2_u64.pow(31) + 1000 - 1),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: 1000.to_string(),
                index: 2_u64.pow(31) + 1000 - 1,
                size: 32,
                offset: 0
            }]))
        );

        assert_eq!(
            a.get_node(0, 2 * (2_u64.pow(31) - 1)),
            Node::Leaf(Leaf::Basic(vec![Basic {
                ident: (2_u64.pow(31) - 1).to_string(),
                index: 2 * (2_u64.pow(31) - 1),
                size: 32,
                offset: 0
            }]))
        );
    }
}
