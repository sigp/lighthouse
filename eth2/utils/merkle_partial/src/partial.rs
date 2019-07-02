use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::Field;
use hashing::hash;
use tree_hash::BYTES_PER_CHUNK;

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
pub trait Partial {
    /// Gets a reference to the struct's `Cache` which stores known nodes.
    fn get_cache(&self) -> &Cache;

    /// Gets a mutable reference to the struct's `Cache` which stores known nodes.
    fn get_cache_mut(&mut self) -> &mut Cache;

    /// Gets a reference to the `Node`s coresponding to the struct.
    fn get_fields(&self) -> &Vec<Box<Field>>;

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    fn get_partial(&self, path: Vec<&str>) -> Result<SerializedPartial> {
        let cache = self.get_cache();
        let fields = self.get_fields();

        let (indicies, chunks) = get_partial_helper(cache, fields, path, &mut vec![], &mut vec![])?;

        Ok(SerializedPartial { indicies, chunks })
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

    fn path_was_loaded(&self, path: Vec<&str>) -> bool {
        true
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
        Some(index - 1)
    } else {
        Some(index + 1)
    }
}

/// Recursively traverse the `fields` matching the appropriate `path` element with its index,
/// eventually returning the `indicies` and `chunks` needed to generate the partial for the path.
fn get_partial_helper(
    cache: &Cache,
    fields: &Vec<Box<Field>>,
    path: Vec<&str>,
    indicies: &mut Vec<NodeIndex>,
    chunks: &mut Vec<u8>,
) -> Result<(Vec<NodeIndex>, Vec<u8>)> {
    if path.len() == 0 {
        return Ok((indicies.clone(), chunks.clone()));
    }

    let element = path[0];

    for field in fields {
        if element == field.ident {
            let index = field.index;

            // Capture the matching node only if on leaf
            if path.len() == 1 {
                indicies.push(index);
                chunks.extend(cache.get(index).ok_or(Error::MissingNode(index))?);
            }

            // Capture sibling node
            if let Some(sibling) = get_sibling_index(index) {
                indicies.push(sibling);
                chunks.extend(cache.get(sibling).ok_or(Error::MissingNode(sibling))?);
            }

            return get_partial_helper(
                cache,
                &field.children,
                path[1..].to_vec(),
                indicies,
                chunks,
            );
        }
    }

    Err(Error::InvalidPath(element.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]
    use super::*;
    use ethereum_types::U256;

    struct A {
        // Should be added by derive macro
        cache: Cache,
        fields: Vec<Box<Field>>,
    }

    impl Partial for A {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }

        fn get_fields(&self) -> &Vec<Box<Field>> {
            &self.fields
        }
    }

    struct B {
        a: U256,
        b: U256,
        // Should be added by derive macro
        cache: Cache,
        fields: Vec<Box<Field>>,
    }

    impl Partial for B {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
        }

        fn get_fields(&self) -> &Vec<Box<Field>> {
            &self.fields
        }
    }

    #[test]
    fn get_partial_from_path() {
        let one = U256::from(1);
        let two = U256::from(2);

        let mut arr = [0_u8; 64];

        one.to_little_endian(&mut arr[0..32]);
        two.to_little_endian(&mut arr[32..]);

        let partial = SerializedPartial {
            indicies: vec![1, 2],
            chunks: arr.to_vec(),
        };

        let one = Field {
            ident: "a",
            index: 1,
            children: vec![],
        };

        let two = Field {
            ident: "b",
            index: 1,
            children: vec![],
        };

        let mut b = B {
            a: 0.into(),
            b: 0.into(),
            cache: Cache::new(),
            fields: vec![Box::new(one), Box::new(two)],
        };

        b.load_partial(partial.clone()).unwrap();

        assert_eq!(partial, b.get_partial(vec!["a"]).unwrap());
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

        let p = A {
            cache,
            fields: vec![],
        };

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

        let mut p = A {
            cache,
            fields: vec![],
        };
        assert_eq!(p.fill(), Ok(()));
        assert_eq!(p.is_valid(), true);
    }
}
