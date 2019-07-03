use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use hashing::hash;
use tree_hash::BYTES_PER_CHUNK;

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
pub trait Partial {
    /// Gets a reference to the struct's `Cache` which stores known nodes.
    fn get_cache(&self) -> &Cache;

    /// Gets a mutable reference to the struct's `Cache` which stores known nodes.
    fn get_cache_mut(&mut self) -> &mut Cache;

    /// Gets the `Node` coresponding to the general index.
    fn get_node(&self, index: NodeIndex) -> Node;

    /// Assigns the data in a chunk to their respective fields in the struct
    fn chunk_to_fields(&mut self, index: NodeIndex, chunk: Vec<u8>) -> Result<()>;

    /// Returns the height of the struct (e.g. log(next_power_of_two(pack(self).len())))
    fn height(&self) -> usize;

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    fn get_partial(&self, path: Vec<&str>) -> Result<SerializedPartial> {
        let (indices, chunks) = self.get_partial_helper(
            self.get_cache(),
            1,
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
            let node = self.get_node(*index);

            self.get_cache_mut().insert(*index, chunk.clone());

            if let Node::Leaf(Leaf::Basic(_)) = node {
                self.chunk_to_fields(*index, chunk)?;
            }
        }

        Ok(())
    }

    /// Return whether a path has been loade into the partial.
    fn is_path_loaded(&self, path: Vec<&str>) -> bool {
        let height = self.height();

        let mut leaves: Vec<Node> = vec![];
        for i in 2_u32.pow(height as u32)..2_u32.pow(height as u32 + 1) {
            leaves.push(self.get_node(i as NodeIndex));
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
            let parent = node / 2;
            let left = node & (-2_i64 as NodeIndex);
            let right = node | 1;

            if node > 1 {
                let left = match cache.get(left) {
                    Some(n) => n,
                    None => return false,
                };

                let right = match cache.get(right) {
                    Some(n) => n,
                    None => return false,
                };

                let parent = match cache.get(parent) {
                    Some(n) => n,
                    None => return false,
                };

                if hash_children(&left, &right) != *parent {
                    return false;
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
            let node = nodes[position];

            // Calculate the parent node if both children are present
            if cache.contains_node(node)
                && cache.contains_node(node ^ 1)
                && !cache.contains_node(node / 2)
            {
                let parent = node / 2;
                let left = node & (-2_i64 as u64);
                let right = node | 1;

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
        path: Vec<&str>,
        indices: &mut Vec<NodeIndex>,
        chunks: &mut Vec<u8>,
    ) -> Result<(Vec<NodeIndex>, Vec<u8>)> {
        if path.len() == 0 {
            return Ok((indices.clone(), chunks.clone()));
        }

        let path_element = path[0];

        let mut leaves: Vec<Node> = vec![];
        for i in 2_u32.pow(height as u32)..2_u32.pow(height as u32 + 1) {
            leaves.push(self.get_node(i as NodeIndex));
        }

        for leaf in leaves {
            if let Node::Leaf(Leaf::Basic(chunk_fields)) = leaf {
                for field in chunk_fields {
                    if path_element == field.ident {
                        let index = field.index;

                        indices.push(index);
                        chunks.extend(cache.get(index).ok_or(Error::MissingNode(index))?);

                        let mut visitor = index;

                        while visitor > root {
                            if let Some(sibling) = get_sibling_index(visitor) {
                                indices.push(sibling);
                                chunks
                                    .extend(cache.get(sibling).ok_or(Error::MissingNode(sibling))?);
                            }

                            visitor /= 2;
                        }

                        // should recurse here for container types
                        return Ok((indices.clone(), chunks.clone()));
                    }
                }
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

/// Returns the index of a node's sibling.
fn get_sibling_index(index: NodeIndex) -> Option<NodeIndex> {
    if index == 0 {
        return None;
    }

    if index % 2 == 0 {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::super::vec_to_array;
    use super::*;
    use crate::field::{Basic, Leaf, Node, Value};
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
    //        a_root(1)
    //       /         \
    //     i(2)       i(3)
    //    /   \       /   \
    //  a(4) b(5)  c,d(6) p(7)
    //
    // n(i) => n = node type, i = general index
    // i = intermediate, p = padding

    // Should be implemented by derive macro
    impl Partial for A {
        fn height(&self) -> usize {
            2
        }

        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }

        fn get_node(&self, index: NodeIndex) -> Node {
            match index {
                1 => Node::Root(Value { index: 1 }),
                2 => Node::Intermediate(Value { index: 2 }),
                3 => Node::Intermediate(Value { index: 3 }),
                4 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "a",
                    index: 4,
                    size: 32,
                    offset: 0,
                }])),
                5 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "b",
                    index: 5,
                    size: 32,
                    offset: 0,
                }])),
                6 => Node::Leaf(Leaf::Basic(vec![
                    Basic {
                        ident: "c",
                        index: 6,
                        size: 16,
                        offset: 0,
                    },
                    Basic {
                        ident: "d",
                        index: 6,
                        size: 16,
                        offset: 16,
                    },
                ])),
                7 => Node::Leaf(Leaf::Padding()),
                n => unimplemented!("get node: {:?}", n),
            }
        }

        fn chunk_to_fields(&mut self, index: NodeIndex, chunk: Vec<u8>) -> Result<()> {
            unsafe {
                match index {
                    4 => self.a = transmute::<[u8; 32], U256>(vec_to_array!(chunk, 32)),
                    5 => self.b = transmute::<[u8; 32], U256>(vec_to_array!(chunk, 32)),
                    6 => {
                        self.c = transmute::<[u8; 16], u128>(vec_to_array!(chunk[0..16], 16));
                        self.d = transmute::<[u8; 16], u128>(vec_to_array!(chunk[16..32], 16));
                    }
                    7 => (),
                    n => unimplemented!("chunk_to_field: {:?}", n),
                }
            }

            Ok(())
        }
    }

    #[test]
    fn is_valid_partial() {
        let mut cache: Cache = Cache::new();

        // leaf nodes
        cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        // intermediate nodes
        cache.insert(3, hash_children(&cache[6], &cache[7]));
        cache.insert(2, hash_children(&cache[4], &cache[5]));

        // root node
        cache.insert(1, hash_children(&cache[2], &cache[3]));

        let p = A {
            a: 1.into(),
            b: 2.into(),
            c: 3,
            d: 4,
            cache,
        };

        assert_eq!(p.is_valid(), true);
    }

    #[test]
    fn can_fill_cache() {
        let mut cache = Cache::new();

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

        assert_eq!(a.is_valid(), false);
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
            indices: vec![4, 5, 6, 7],
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
        let one = U256::from(1);
        let two = U256::from(2);

        let mut arr = [0_u8; 96];

        one.to_little_endian(&mut arr[0..32]);
        two.to_little_endian(&mut arr[32..64]);
        let three: &[u8] = &hash_children(&arr[0..32], &arr[32..64]);
        arr[64..96].copy_from_slice(three);

        let partial = SerializedPartial {
            indices: vec![4, 5, 3],
            chunks: arr.to_vec(),
        };

        let mut a = A::default();

        assert_eq!(a.load_partial(partial.clone()), Ok(()));
        assert_eq!(Ok(partial), a.get_partial(vec!["a"]));
    }
}
