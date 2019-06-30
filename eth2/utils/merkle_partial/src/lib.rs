use hashing::hash;
use ssz::BYTES_PER_LENGTH_OFFSET;
use std::collections::HashMap;
use tree_hash::BYTES_PER_CHUNK;

#[derive(Debug, PartialEq)]
pub enum ParsePartialError {
    // The node is not equal to h(left, right)
    InvalidNode(u64),
    // The partial is incomplete
    MissingNode(u64),
}

pub type Result<T> = std::result::Result<T, ParsePartialError>;

#[derive(Debug, Default)]
pub struct SerializedPartial {
    indicies: Vec<u64>,
    chunks: Vec<u8>, // vec<bytes32>
}

pub struct Partial {
    cache: HashMap<u64, Vec<u8>>,
}

impl Partial {
    pub fn is_valid(&self) -> bool {
        for (key, _) in &self.cache {
            let key = *key;
            let parent = key / 2;
            let left = key & (-2_i64 as u64);
            let right = key | 1;

            if key > 1 {
                let h = hash_children(
                    match self.cache.get(&left) {
                        Some(n) => n,
                        None => return false,
                    },
                    match self.cache.get(&right) {
                        Some(n) => n,
                        None => return false,
                    },
                );

                // Child nodes should always hash to their parent
                if self.cache[&parent] != h {
                    return false;
                }
            }
        }

        true
    }

    pub fn fill(&mut self) -> Result<()> {
        let mut keys: Vec<u64> = self.cache.keys().clone().map(|x| x.to_owned()).collect();
        keys.sort_by(|a, b| b.cmp(a));

        let mut position = 0;

        while position < keys.len() {
            let key = keys[position];

            if self.cache.contains_key(&key)
                && self.cache.contains_key(&(key ^ 1))
                && !self.cache.contains_key(&(key / 2))
            {
                let parent = key / 2;
                let left = key & (-2_i64 as u64);
                let right = key | 1;

                let h = hash_children(
                    match self.cache.get(&left) {
                        Some(n) => n,
                        None => return Err(ParsePartialError::MissingNode(left)),
                    },
                    match self.cache.get(&right) {
                        Some(n) => n,
                        None => return Err(ParsePartialError::MissingNode(right)),
                    },
                );

                self.cache.insert(parent, h);
                keys.push(parent);
            }

            position += 1;
        }

        Ok(())
    }
}

trait PartialObject {
    fn get_partial(&self, path: &str) -> Vec<u8> {
        unimplemented!()
    }

    fn load_partial(&mut self, partial: Partial) -> Result<()> {
        unimplemented!()
    }
}

fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let children: Vec<u8> = left.iter().cloned().chain(right.iter().cloned()).collect();
    hash(&children)
}

impl From<&SerializedPartial> for Partial {
    fn from(partial: &SerializedPartial) -> Self {
        let mut cache: HashMap<u64, Vec<u8>> = HashMap::new();

        for (i, index) in partial.indicies.iter().enumerate() {
            let begin = i * BYTES_PER_CHUNK;
            let end = begin + BYTES_PER_CHUNK;
            cache.insert(*index, partial.chunks[begin..end].into());
        }

        Self { cache }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct A {
        a: usize,
        b: usize,
    }

    impl PartialObject for A {}

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

        let p = Partial { cache };

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

        let mut p = Partial { cache };
        assert_eq!(p.fill(), Ok(()));
        assert_eq!(p.is_valid(), true);
    }
}
