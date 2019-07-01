use hashing::hash;
use ssz::BYTES_PER_LENGTH_OFFSET;

use tree_hash::BYTES_PER_CHUNK;

#[derive(Debug, PartialEq)]
pub enum Error {
    // The node is not equal to h(left, right)
    InvalidNode(u64),
    // The partial is incomplete
    MissingNode(u64),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct SerializedPartial {
    indicies: Vec<u64>,
    chunks: Vec<u8>, // vec<bytes32>
}

pub trait Partial {
    fn get(&self, index: u64) -> Option<&Vec<u8>>;
    fn insert(&mut self, index: u64, chunk: Vec<u8>) -> Option<Vec<u8>>;
    fn nodes(&self) -> Vec<u64>;
    fn contains_node(&self, index: u64) -> bool;

    fn get_partial(&self, path: &str) -> SerializedPartial {
        unimplemented!()
    }

    fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        for (i, index) in partial.indicies.iter().enumerate() {
            let begin = i * BYTES_PER_CHUNK;
            let end = begin + BYTES_PER_CHUNK;
            self.insert(*index, partial.chunks[begin..end].into());
        }

        Ok(())
    }

    fn is_valid(&self) -> bool {
        for node in self.nodes() {
            let parent = node / 2;
            let left = node & (-2_i64 as u64);
            let right = node | 1;

            if node > 1 {
                let left = match self.get(left) {
                    Some(n) => n,
                    None => return false,
                };

                let right = match self.get(right) {
                    Some(n) => n,
                    None => return false,
                };

                let parent = match self.get(parent) {
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

    fn fill(&mut self) -> Result<()> {
        let mut nodes: Vec<u64> = self.nodes();
        nodes.sort_by(|a, b| b.cmp(a));

        let mut position = 0;

        while position < nodes.len() {
            let node = nodes[position];

            // Calculate the parent node if both children are present
            if self.contains_node(node)
                && self.contains_node(node ^ 1)
                && !self.contains_node(node / 2)
            {
                let parent = node / 2;
                let left = node & (-2_i64 as u64);
                let right = node | 1;

                let h = hash_children(
                    &self.get(left).ok_or(Error::MissingNode(left))?,
                    &self.get(right).ok_or(Error::MissingNode(right))?,
                );

                self.insert(parent, h);
                nodes.push(parent);
            }

            position += 1;
        }

        Ok(())
    }
}

fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let children: Vec<u8> = left.iter().cloned().chain(right.iter().cloned()).collect();
    hash(&children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct A {
        // Should be added by derive macro
        cache: HashMap<u64, Vec<u8>>,
    }

    impl Partial for A {
        fn get(&self, index: u64) -> Option<&Vec<u8>> {
            self.cache.get(&index)
        }

        fn insert(&mut self, index: u64, chunk: Vec<u8>) -> Option<Vec<u8>> {
            self.cache.insert(index, chunk)
        }

        fn nodes(&self) -> Vec<u64> {
            self.cache.keys().clone().map(|x| x.to_owned()).collect()
        }

        fn contains_node(&self, index: u64) -> bool {
            self.cache.contains_key(&index)
        }
    }

    #[test]
    fn is_valid_partial_bigger() {
        let mut cache: HashMap<u64, Vec<u8>> = HashMap::new();

        // leaf nodes
        cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        // intermediate nodes
        cache.insert(3, hash_children(&cache[&6], &cache[&7]));
        cache.insert(2, hash_children(&cache[&4], &cache[&5]));

        // root node
        cache.insert(1, hash_children(&cache[&2], &cache[&3]));

        let p = A { cache };

        assert_eq!(p.is_valid(), true);
    }

    #[test]
    fn can_fill() {
        let mut cache: HashMap<u64, Vec<u8>> = HashMap::new();

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
