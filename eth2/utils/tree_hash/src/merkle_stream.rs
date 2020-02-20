use crate::{get_zero_hash, Hash256};
use eth2_hashing::{Context, SHA256};
use std::mem;
use std::num::NonZeroUsize;

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

fn is_left_node(i: usize) -> bool {
    i % 2 == 0
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

    pub fn process_leaf(&mut self, leaf: &Hash256) {
        if is_left_node(self.next_leaf) {
            self.half_nodes
                .push(HalfNode::new(get_parent(self.next_leaf), leaf))
        } else {
            self.process_internal(get_parent(self.next_leaf), leaf)
        }

        self.next_leaf += 1;
    }

    fn process_internal(&mut self, mut id: usize, internal: &Hash256) {
        let mut digest = *internal;

        loop {
            match self.half_nodes.last() {
                Some(node) if node.id == id => {
                    digest = self.half_nodes.pop().unwrap().finish(&digest);
                    if id == 1 {
                        self.root = Some(Hash256::from_slice(digest.as_ref()));
                        break;
                    } else {
                        id = get_parent(id);
                    }
                }
                _ => {
                    self.half_nodes.push(HalfNode::new(id, &digest));
                    break;
                }
            }
        }
    }

    pub fn finish(self) -> Hash256 {
        if let Some(root) = self.root {
            root
        } else {
            /*
            loop {
                let node = self.half_nodes.last().unwrap();
            }
            */
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkleize_standard;

    fn do_test(leaves: &[Hash256], depth: usize) {
        let standard_bytes = leaves
            .iter()
            .map(|hash| hash.as_bytes().to_vec())
            .flatten()
            .collect::<Vec<_>>();

        let standard_root = merkleize_standard(&standard_bytes);
        let merklizer_root = {
            let mut m =
                MerkleStream::new(NonZeroUsize::new(depth).expect("depth should not be zero"));
            for leaf in leaves.iter() {
                m.process_leaf(leaf);
            }
            m.finish()
        };

        assert_eq!(standard_root, merklizer_root, "should match reference root");
    }

    fn with_len(leaves: u64, height: usize) {
        let leaves = (0..leaves)
            .map(|i| Hash256::from_low_u64_be(i))
            .collect::<Vec<_>>();
        do_test(&leaves, height)
    }

    #[test]
    fn test() {
        with_len(2, 2);
        with_len(4, 3);
        with_len(8, 4);
        with_len(16, 5);
        with_len(32, 6);
        with_len(64, 7);
    }
}
