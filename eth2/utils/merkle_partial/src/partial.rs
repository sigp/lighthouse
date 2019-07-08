use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use crate::merkle_tree_overlay::MerkleTreeOverlay;
use crate::path::Path;
use crate::tree_arithmetic::{expand_tree_index, sibling_index};
use hashing::hash;
use tree_hash::BYTES_PER_CHUNK;

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
pub trait Partial: MerkleTreeOverlay {
    /// Gets a reference to the struct's `Cache` which stores known nodes.
    fn get_cache(&self) -> &Cache;

    /// Gets a mutable reference to the struct's `Cache` which stores known nodes.
    fn get_cache_mut(&mut self) -> &mut Cache;

    /// Assigns the data in a chunk to their respective fields in the struct
    fn chunk_to_fields(&mut self, node: Node, chunk: Vec<u8>) -> Result<()>;

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    fn get_partial(&self, path: Vec<Path>) -> Result<SerializedPartial> {
        let (indices, chunks) = self.get_partial_helper(
            self.get_cache(),
            0,
            self.height(),
            path,
            &mut vec![],
            &mut vec![],
        )?;

        Ok(SerializedPartial { indices, chunks })
    }

    /// Populates the struct's values and cache with a `SerializedPartial`.
    fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        for (i, index) in partial.indices.iter().enumerate() {
            let chunk = partial.chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK].to_vec();
            let node = self.get_node(0, *index);

            self.get_cache_mut().insert(*index, chunk.clone());

            // TODO: should this even be a part of `load_partial`?
            if let Node::Leaf(Leaf::Basic(_)) = node {
                self.chunk_to_fields(node, chunk)?;
            }
        }

        Ok(())
    }

    /// Return whether a path has been loade into the partial.
    fn is_path_loaded(&self, path: Vec<&str>) -> bool {
        let height = self.height();

        let mut leaves: Vec<Node> = vec![];
        for i in 2_u64.pow(height as u32)..(2_u64.pow(height as u32 + 1) - 1) {
            leaves.push(self.get_node(0, i as NodeIndex - 1));
        }

        for leaf in leaves {
            if let Node::Leaf(Leaf::Basic(chunk_fields)) = leaf {
                for field in chunk_fields {
                    if path[0] == field.ident {
                        if let Some(_) = self.get_cache().get(field.index) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Determines if the current merkle tree is valid.
    fn is_valid(&self) -> bool {
        let cache = self.get_cache();
        for node in cache.nodes() {
            let (left, right, parent) = expand_tree_index(node);

            if node > 1 {
                let left = cache.get(left);
                let right = cache.get(right);
                let parent = cache.get(parent);

                if let (Some(left), Some(right), Some(parent)) = (left, right, parent) {
                    if hash_children(&left, &right) != *parent {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Inserts missing nodes into the merkle tree that can be generated from existing nodes.
    fn fill(&mut self) -> Result<()> {
        let cache = self.get_cache_mut();

        let mut nodes: Vec<u64> = cache.nodes();
        nodes.sort_by(|a, b| b.cmp(a));

        let mut position = 0;
        while position < nodes.len() {
            let (left, right, parent) = expand_tree_index(nodes[position]);

            if cache.contains_node(left)
                && cache.contains_node(right)
                && !cache.contains_node(parent)
            {
                let h = hash_children(
                    &cache.get(left).ok_or(Error::MissingNode(left))?,
                    &cache.get(right).ok_or(Error::MissingNode(right))?,
                );

                cache.insert(parent, h);
                nodes.push(parent);
            }

            position += 1;
        }

        Ok(())
    }

    /// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
    /// eventually returning the `indicies` and `chunks` needed to generate the partial for the path.
    fn get_partial_helper(
        &self,
        cache: &Cache,
        root: NodeIndex,
        height: usize,
        path: Vec<Path>,
        indices: &mut Vec<NodeIndex>,
        chunks: &mut Vec<u8>,
    ) -> Result<(Vec<NodeIndex>, Vec<u8>)> {
        if path.len() == 0 {
            return Ok((indices.clone(), chunks.clone()));
        }

        let path_element = &path[0];

        let leaves = match path_element.clone() {
            Path::Ident(_) => {
                let mut ret: Vec<Node> = vec![];
                for i in 2_u64.pow(height as u32)..(2_u64.pow(height as u32 + 1) - 1) {
                    ret.push(self.get_node(0, i as NodeIndex - 1));
                }

                ret
            }
            Path::Index(i) => {
                let first_leaf = 2_u64.pow(height as u32) - 1;
                vec![self.get_node(0, first_leaf + i)]
            }
        };

        for leaf in leaves {
            match leaf {
                Node::Leaf(Leaf::Basic(chunk_fields)) => {
                    for field in chunk_fields {
                        if path_element.to_string() == field.ident {
                            let index = field.index;

                            indices.push(index);
                            chunks.extend(cache.get(index).ok_or(Error::MissingNode(index))?);

                            let mut visitor = index;

                            while visitor > root {
                                let sibling = sibling_index(visitor);
                                let left = 2 * sibling + 1;
                                let right = 2 * sibling + 2;

                                if !(indices.contains(&left) && indices.contains(&right)) {
                                    indices.push(sibling);
                                    chunks.extend(
                                        cache.get(sibling).ok_or(Error::MissingNode(sibling))?,
                                    );
                                }

                                visitor /= 2;
                            }

                            // should recurse here for container types
                            return Ok((indices.clone(), chunks.clone()));
                        }
                    }
                }
                Node::Composite(field) => {
                    if path_element.to_string() == field.ident {
                        let index = field.index;

                        indices.push(index);
                        chunks.extend(cache.get(index).ok_or(Error::MissingNode(index))?);

                        let mut visitor = index;

                        while visitor > root {
                            let sibling = sibling_index(visitor);
                            indices.push(sibling);
                            chunks.extend(cache.get(sibling).ok_or(Error::MissingNode(sibling))?);

                            visitor /= 2;
                        }

                        println!("oh shit");
                        return self.get_partial_helper(
                            cache,
                            index,
                            field.height,
                            path[1..].to_vec(),
                            indices,
                            chunks,
                        );
                    }
                }
                _ => (),
            }
        }

        Err(Error::InvalidPath(path_element.to_string()))
    }
}

/// Helper function that appends `right` to `left` and hashes the result.
fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let children: Vec<u8> = left.iter().cloned().chain(right.iter().cloned()).collect();
    hash(&children)
}

#[cfg(test)]
mod tests {
    use super::super::vec_to_array;
    use super::*;
    use crate::field::{Basic, Composite, Leaf, Node};
    use ethereum_types::U256;
    use std::mem::transmute;

    #[derive(Debug, Default)]
    struct A {
        a: U256,
        b: U256,
        c: u128,
        d: u128,
        // Should be added by derive macro
        cache: Cache,
    }

    // A's merkle tree
    //
    //        a_root(0)
    //       /         \
    //     i(1)       i(2)
    //    /   \       /   \
    //  a(3) b(4)  c,d(5) p(6)
    //
    // n(i) => n = node type, i = general index
    // i = intermediate, p = padding

    // Should be implemented by derive macro
    impl MerkleTreeOverlay for A {
        fn height(&self) -> usize {
            2
        }

        fn get_node(&self, _root: NodeIndex, index: NodeIndex) -> Node {
            match index {
                0 => Node::Composite(Composite {
                    ident: "",
                    index: 1,
                    height: self.height(),
                }),
                1 => Node::Intermediate(2),
                2 => Node::Intermediate(3),
                3 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "a".to_string(),
                    index: 4,
                    size: 32,
                    offset: 0,
                }])),
                4 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "b".to_string(),
                    index: 5,
                    size: 32,
                    offset: 0,
                }])),
                5 => Node::Leaf(Leaf::Basic(vec![
                    Basic {
                        ident: "c".to_string(),
                        index: 6,
                        size: 16,
                        offset: 0,
                    },
                    Basic {
                        ident: "d".to_string(),
                        index: 6,
                        size: 16,
                        offset: 16,
                    },
                ])),
                6 => Node::Leaf(Leaf::Padding()),
                n => unimplemented!("get node: {:?}", n),
            }
        }
    }

    impl Partial for A {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }

        fn chunk_to_fields(&mut self, node: Node, chunk: Vec<u8>) -> Result<()> {
            unsafe {
                match node {
                    Node::Leaf(Leaf::Basic(n)) => match n[0].index {
                        4 => self.a = transmute::<[u8; 32], U256>(vec_to_array!(chunk, 32)),
                        5 => self.b = transmute::<[u8; 32], U256>(vec_to_array!(chunk, 32)),
                        6 => {
                            self.c = transmute::<[u8; 16], u128>(vec_to_array!(chunk[0..16], 16));
                            self.d = transmute::<[u8; 16], u128>(vec_to_array!(chunk[16..32], 16));
                        }
                        7 => (),
                        n => unimplemented!("chunk_to_field: {:?}", n),
                    },
                    _ => (),
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct B {
        a: Vec<u128>,
        // Should be added by proc macro
        cache: Cache,
    }

    // B's merkle tree
    //
    //        b_root(0)
    //       /         \
    // b_data_root(1) b_len(2)
    //    /   \
    //  . . . . .
    //

    // Should be implemented by derive macro
    impl MerkleTreeOverlay for B {
        fn height(&self) -> usize {
            0
        }

        fn get_node(&self, root: NodeIndex, index: NodeIndex) -> Node {
            self.a.get_node(root, index)
        }
    }

    impl Partial for B {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }

        fn chunk_to_fields(&mut self, node: Node, chunk: Vec<u8>) -> Result<()> {
            const CAPPED_DEPTH: NodeIndex = 32;
            const LAST_INTERNAL: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 2;
            const FIRST_LEAF: NodeIndex = (1_u64 << (CAPPED_DEPTH - 1)) - 1;
            const LAST_LEAF: NodeIndex = (1_u64 << CAPPED_DEPTH) - 1;

            unsafe {
                match node {
                    Node::Leaf(Leaf::Basic(leaves)) => match leaves[0].index {
                        0...LAST_INTERNAL => (),
                        FIRST_LEAF...LAST_LEAF => {
                            for leaf in leaves {
                                let ident: usize = leaf.ident.parse().unwrap();
                                let begin: usize = leaf.offset as usize;
                                let end: usize = leaf.offset as usize + leaf.size;

                                self.a[ident] = transmute::<[u8; 16], u128>(vec_to_array!(
                                    chunk[begin..end],
                                    16
                                ));
                            }
                        }
                        n => unimplemented!("chunk_to_field: {:?}", n),
                    },
                    _ => (),
                }
            }
            Ok(())
        }
    }

    #[test]
    fn is_valid_partial() {
        let mut cache: Cache = Cache::default();

        // leaf nodes
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);
        cache.insert(3, vec![3; BYTES_PER_CHUNK]);

        // intermediate nodes
        cache.insert(2, hash_children(&cache[5], &cache[6]));
        cache.insert(1, hash_children(&cache[3], &cache[4]));

        // root node
        cache.insert(0, hash_children(&cache[1], &cache[2]));

        let mut a = A::default();
        a.cache = cache;

        assert_eq!(a.is_valid(), true);
    }

    #[test]
    fn can_fill_cache() {
        let mut cache = Cache::default();

        // leaf nodes
        cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        let mut a = A {
            a: 1.into(),
            b: 2.into(),
            c: 3,
            d: 4,
            cache,
        };

        assert_eq!(a.fill(), Ok(()));
        assert_eq!(a.is_valid(), true);
    }

    #[test]
    fn load_partial_basic_container() {
        let one = U256::from(1);
        let two = U256::from(2);

        let mut arr = [0_u8; 128];

        one.to_little_endian(&mut arr[0..32]);
        two.to_little_endian(&mut arr[32..64]);
        arr[64] = 3;
        arr[80] = 4;

        let partial = SerializedPartial {
            indices: vec![3, 4, 5, 6],
            chunks: arr.to_vec(),
        };

        let mut a = A::default();

        assert_eq!(a.load_partial(partial.clone()), Ok(()));

        assert_eq!(a.is_path_loaded(vec!["a"]), true);
        assert_eq!(a.a, one);

        assert_eq!(a.is_path_loaded(vec!["b"]), true);
        assert_eq!(a.b, two);

        assert_eq!(a.is_path_loaded(vec!["c"]), true);
        assert_eq!(a.c, 3);

        assert_eq!(a.is_path_loaded(vec!["d"]), true);
        assert_eq!(a.d, 4);

        assert_eq!(a.is_path_loaded(vec!["e"]), false);
    }

    #[test]
    fn get_partial_basic_container() {
        let three = U256::from(1);
        let four = U256::from(2);

        let mut arr = [0_u8; 96];

        four.to_little_endian(&mut arr[0..32]);
        three.to_little_endian(&mut arr[32..64]);

        let two: &[u8] = &hash_children(&arr[64..96], &arr[64..96]);

        arr[64..96].copy_from_slice(two);

        let partial = SerializedPartial {
            indices: vec![4, 3, 2],
            chunks: arr.to_vec(),
        };

        let mut a = A::default();

        assert_eq!(a.load_partial(partial.clone()), Ok(()));
        assert_eq!(a.fill(), Ok(()));
        assert_eq!(
            Ok(partial),
            a.get_partial(vec![Path::Ident("a".to_string())])
        );
    }

    #[test]
    #[ignore]
    fn get_partial_list() {
        let mut chunk = [0_u8; 64];
        chunk[15] = 1;
        chunk[31] = 2;

        let partial = SerializedPartial {
            indices: vec![2_u64.pow(31) - 1, 2_u64.pow(31) - 1],
            chunks: chunk.to_vec(),
        };

        let mut b = B::default();

        assert_eq!(b.load_partial(partial.clone()), Ok(()));

        println!(
            "{:?}",
            b.get_partial(vec![Path::Ident("a".to_string()), Path::Index(0)])
        );

        // assert_eq!(a.load_partial(partial.clone()), Ok(()));
        // assert_eq!(Ok(partial), a.get_partial(vec!["a"]));
    }

}
