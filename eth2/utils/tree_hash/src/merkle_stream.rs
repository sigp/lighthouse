use crate::{get_zero_hash, Hash256};
use eth2_hashing::{Context, SHA256};
use std::mem;
use std::num::NonZeroUsize;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The maximum number of leaves defined by the initialization `depth` has been exceed.
    MaximumLeavesExceeded { max_leaves: usize },
}

struct HalfNode {
    context: Context,
    id: usize,
}

impl HalfNode {
    fn new(id: usize, left: &Hash256) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(left.as_bytes());

        Self { context, id }
    }

    fn finish(mut self, right: &Hash256) -> Hash256 {
        self.context.update(right.as_bytes());
        let digest = self.context.finish();
        Hash256::from_slice(digest.as_ref())
    }

    fn finish_with_zero_hash(mut self) -> Hash256 {
        let total_bits = mem::size_of::<usize>() * 8;
        let height = total_bits - self.id.leading_zeros() as usize - 1;
        self.finish(&Hash256::from_slice(get_zero_hash(height)))
    }
}

struct MerkleStream {
    // TODO: smallvec.
    half_nodes: Vec<HalfNode>,
    depth: usize,
    next_leaf: usize,
    root: Option<Hash256>,
}

fn get_parent(i: usize) -> usize {
    i / 2
}

fn get_depth(i: usize) -> usize {
    let total_bits = mem::size_of::<usize>() * 8;
    total_bits - i.leading_zeros() as usize - 1
}

impl MerkleStream {
    pub fn new(depth: NonZeroUsize) -> Self {
        let depth = depth.get();

        Self {
            half_nodes: vec![],
            depth,
            next_leaf: 1 << (depth - 1),
            root: None,
        }
    }

    pub fn process_leaf(&mut self, leaf: &Hash256) -> Result<(), Error> {
        let max_leaves = 1 << (self.depth + 1);

        if self.next_leaf > max_leaves {
            return Err(Error::MaximumLeavesExceeded { max_leaves });
        } else if self.next_leaf == 1 {
            self.root = Some(*leaf)
        } else if self.next_leaf % 2 == 0 {
            self.process_left_node(self.next_leaf, leaf)
        } else {
            self.process_right_node(self.next_leaf, *leaf)
        }

        self.next_leaf += 1;

        Ok(())
    }

    pub fn finish(mut self) -> Hash256 {
        loop {
            if let Some(root) = self.root {
                break root;
            } else {
                if let Some(node) = self.half_nodes.last() {
                    let right_child = node.id * 2 + 1;
                    let digest = Hash256::from_slice(get_zero_hash(
                        self.depth - (get_depth(right_child) + 1),
                    ));

                    self.process_right_node(right_child, digest);
                } else if self.next_leaf == 1 {
                    break Hash256::zero();
                } else {
                    let digest = &Hash256::from_slice(get_zero_hash(
                        self.depth - (get_depth(self.next_leaf) + 1),
                    ));

                    self.process_left_node(self.next_leaf, &digest)
                }
            }
        }
    }

    fn process_left_node(&mut self, id: usize, digest: &Hash256) {
        println!("left {}", id);
        self.half_nodes.push(HalfNode::new(get_parent(id), digest))
    }

    fn process_right_node(&mut self, id: usize, mut digest: Hash256) {
        println!("right {}", id);
        let mut parent = get_parent(id);

        loop {
            match self.half_nodes.last() {
                Some(node) if node.id == parent => {
                    digest = self
                        .half_nodes
                        .pop()
                        .expect("if .last() is Some then .pop() must succeed")
                        .finish(&digest);
                    if parent == 1 {
                        self.root = Some(Hash256::from_slice(digest.as_ref()));
                        break;
                    } else {
                        parent = get_parent(parent);
                    }
                }
                _ => {
                    self.half_nodes.push(HalfNode::new(parent, &digest));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkleize_padded;

    fn do_test(leaves: &[Hash256], depth: usize) {
        let reference_bytes = leaves
            .iter()
            .map(|hash| hash.as_bytes().to_vec())
            .flatten()
            .collect::<Vec<_>>();

        let reference_root = merkleize_padded(&reference_bytes, 1 << (depth - 1));
        let merklizer_root = {
            let mut m =
                MerkleStream::new(NonZeroUsize::new(depth).expect("depth should not be zero"));
            for leaf in leaves.iter() {
                m.process_leaf(leaf).expect("should process leaf");
            }
            m.finish()
        };

        assert_eq!(
            reference_root, merklizer_root,
            "should match reference root"
        );
    }

    fn with_len(leaves: u64, height: usize) {
        let leaves = (0..leaves)
            .map(|i| Hash256::from_low_u64_be(i))
            .collect::<Vec<_>>();
        do_test(&leaves, height)
    }

    #[test]
    fn height() {
        assert_eq!(get_depth(1), 0);
        assert_eq!(get_depth(2), 1);
        assert_eq!(get_depth(3), 1);
        assert_eq!(get_depth(4), 2);
        assert_eq!(get_depth(5), 2);
        assert_eq!(get_depth(6), 2);
        assert_eq!(get_depth(7), 2);
        assert_eq!(get_depth(8), 3);
    }

    #[test]
    fn full_trees() {
        with_len(1, 1);
        with_len(2, 2);
        with_len(4, 3);
        with_len(8, 4);
        with_len(16, 5);
        with_len(32, 6);
        with_len(64, 7);
        with_len(128, 8);
        with_len(256, 9);
        with_len(256, 9);
        with_len(8192, 14);
    }

    #[test]
    fn incomplete_trees() {
        with_len(0, 1);

        with_len(0, 2);
        with_len(1, 2);

        for i in 0..=4 {
            with_len(i, 3);
        }

        for i in 0..=7 {
            with_len(i, 4);
        }

        for i in 0..=15 {
            with_len(i, 5);
        }

        for i in 0..=32 {
            with_len(i, 6);
        }

        for i in 0..=64 {
            with_len(i, 7);
        }

        with_len(0, 14);
        with_len(13, 14);
        with_len(8191, 14);
    }
}
