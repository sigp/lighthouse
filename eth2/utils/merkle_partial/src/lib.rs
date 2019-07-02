use ethereum_types::U256;
use hashing::hash;
use ssz::BYTES_PER_LENGTH_OFFSET;
use std::collections::HashMap;

use tree_hash::BYTES_PER_CHUNK;

pub type NodeIndex = u64;

#[derive(Debug, PartialEq)]
pub enum Error {
    // The node is not equal to h(left, right)
    InvalidNode(NodeIndex),
    // The partial is incomplete
    MissingNode(NodeIndex),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A serializable represenation of a merkle partial
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SerializedPartial {
    indicies: Vec<NodeIndex>,
    chunks: Vec<u8>, // vec<bytes32>
}

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
pub trait Partial {
    /// Gets a reference to the struct's `Cache` which stores known nodes.
    fn get_cache(&self) -> &Cache;

    /// Gets a mutable reference to the struct's `Cache` which stores known nodes.
    fn get_cache_mut(&mut self) -> &mut Cache;

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    fn get_partial(&self, path: &str) -> SerializedPartial {
        unimplemented!()
    }

    /// Populates the struct's values and cache with a `SerializedPartial`.
    fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        let cache = self.get_cache_mut();

        for (i, index) in partial.indicies.iter().enumerate() {
            let begin = i * BYTES_PER_CHUNK;
            let end = begin + BYTES_PER_CHUNK;
            cache.insert(*index, partial.chunks[begin..end].into());
        }

        Ok(())
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

                let h = hash_children(&left, &right);

                // Child nodes should always hash to their parent
                if h != *parent {
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
}

/// Stores the mapping of nodes to their chunks.
pub struct Cache {
    cache: HashMap<NodeIndex, Vec<u8>>,
}

impl Cache {
    /// Instantiate an empty `Cache`.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Gets a reference to the chunk coresponding to the node index.
    fn get(&self, index: NodeIndex) -> Option<&Vec<u8>> {
        self.cache.get(&index)
    }

    /// Sets the chunk for the node index and returns the old value.
    fn insert(&mut self, index: NodeIndex, chunk: Vec<u8>) -> Option<Vec<u8>> {
        self.cache.insert(index, chunk)
    }

    /// Retrieves a vector of set node indicies.
    fn nodes(&self) -> Vec<NodeIndex> {
        self.cache.keys().clone().map(|x| x.to_owned()).collect()
    }

    /// Returns `true` if the cache contains a chunk for the specified node index.
    fn contains_node(&self, index: NodeIndex) -> bool {
        self.cache.contains_key(&index)
    }
}

impl std::ops::Index<usize> for Cache {
    type Output = Vec<u8>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index as u64).expect("node acessible by index")
    }
}

/// Helper function that appends `right` to `left` and hashes the result.
fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let children: Vec<u8> = left.iter().cloned().chain(right.iter().cloned()).collect();
    hash(&children)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct A {
        // Should be added by derive macro
        cache: Cache,
    }

    impl Partial for A {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }
    }

    struct B {
        a: U256,
        b: U256,
        // Should be added by derive macro
        cache: Cache,
    }

    impl Partial for B {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }
    }

    #[test]
    fn abc() {
        let one = U256::from(1);
        let two = U256::from(2);

        let mut arr = [0_u8; 64];

        one.to_little_endian(&mut arr);
        two.to_little_endian(&mut arr[32..]);

        let partial = SerializedPartial {
            indicies: vec![1, 2],
            chunks: arr.to_vec(),
        };

        let mut b = B {
            a: 0.into(),
            b: 0.into(),
            cache: Cache::new(),
        };

        b.load_partial(partial.clone()).unwrap();

        assert_eq!(partial, b.get_partial("a"));
    }

    #[test]
    fn is_valid_partial_bigger() {
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

        let p = A { cache };

        assert_eq!(p.is_valid(), true);
    }

    #[test]
    fn can_fill() {
        let mut cache = Cache::new();

        // leaf nodes
        cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        let mut p = A { cache };
        assert_eq!(p.fill(), Ok(()));
        assert_eq!(p.is_valid(), true);
    }
}
