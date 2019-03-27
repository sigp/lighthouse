use crate::ssz_encode;
use hashing::hash;
use int_to_bytes::int_to_bytes32;

const BYTES_PER_CHUNK: usize = 32;
const HASHSIZE: usize = 32;
const MERKLE_HASH_CHUNCK: usize = 2 * BYTES_PER_CHUNK;

pub struct TreeHashCache<'a> {
    chunk_offset: usize,
    cache: &'a mut [u8],
    chunk_modified: &'a mut [bool],
}

impl<'a> TreeHashCache<'a> {
    pub fn increment(&mut self) {
        self.chunk_offset += 1
    }

    pub fn modify_current_chunk(&mut self, to: &[u8]) -> Option<()> {
        self.modify_chunk(0, to)
    }

    pub fn modify_chunk(&mut self, chunk: usize, to: &[u8]) -> Option<()> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;
        self.cache.get_mut(start..end)?.copy_from_slice(to);

        self.chunk_modified[chunk] = true;

        Some(())
    }

    pub fn changed(&self, chunk: usize) -> Option<bool> {
        self.chunk_modified.get(chunk).cloned()
    }

    pub fn children_modified(&self, parent_chunk: usize) -> Option<bool> {
        let children = children(parent_chunk);

        Some(self.changed(children.0)? | self.changed(children.1)?)
    }

    pub fn hash_children(&self, parent_chunk: usize) -> Option<Vec<u8>> {
        let children = children(parent_chunk);

        let start = children.0 * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK * 2;

        Some(hash(&self.cache.get(start..end)?))
    }

    pub fn just_the_leaves(&mut self, leaves: usize) -> Option<TreeHashCache> {
        let nodes = num_nodes(leaves);
        let internal = nodes - leaves;
        let leaves_start = (self.chunk_offset + internal) * HASHSIZE;

        Some(TreeHashCache {
            chunk_offset: self.chunk_offset + internal,
            cache: self.cache.get_mut(leaves_start..leaves * HASHSIZE)?,
            chunk_modified: self
                .chunk_modified
                .get_mut(self.chunk_offset..self.chunk_offset + leaves)?,
        })
    }
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

pub trait CachedTreeHash {
    fn build_cache_bytes(&self) -> Vec<u8>;

    fn cached_hash_tree_root(&self, other: &Self, cache: &mut TreeHashCache) -> Option<()>;
}

impl CachedTreeHash for u64 {
    fn build_cache_bytes(&self) -> Vec<u8> {
        merkleize(&ssz_encode(self))
    }

    fn cached_hash_tree_root(&self, other: &Self, cache: &mut TreeHashCache) -> Option<()> {
        if self != other {
            cache.modify_current_chunk(&hash(&ssz_encode(self)));
        }

        cache.increment();

        Some(())
    }
}

pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl CachedTreeHash for Inner {
    fn build_cache_bytes(&self) -> Vec<u8> {
        let mut leaves = vec![];

        leaves.append(&mut self.a.build_cache_bytes());
        leaves.append(&mut self.b.build_cache_bytes());
        leaves.append(&mut self.c.build_cache_bytes());
        leaves.append(&mut self.d.build_cache_bytes());

        merkleize(&leaves)
    }

    fn cached_hash_tree_root(&self, other: &Self, cache: &mut TreeHashCache) -> Option<()> {
        let num_leaves = 4;

        let mut leaf_cache = cache.just_the_leaves(num_leaves)?;
        self.a.cached_hash_tree_root(&other.a, &mut leaf_cache)?;
        self.b.cached_hash_tree_root(&other.b, &mut leaf_cache)?;
        self.c.cached_hash_tree_root(&other.c, &mut leaf_cache)?;
        self.d.cached_hash_tree_root(&other.d, &mut leaf_cache)?;

        let nodes = num_nodes(num_leaves);
        let internal_chunks = nodes - num_leaves;

        for chunk in 0..internal_chunks {
            if cache.children_modified(chunk)? {
                cache.modify_chunk(chunk, &cache.hash_children(chunk)?)?;
            }
        }

        Some(())
    }
}

/// A reference function to test against.
pub fn merkleize(values: &[u8]) -> Vec<u8> {
    let leaves = values.len() / HASHSIZE;

    if leaves == 0 || !leaves.is_power_of_two() {
        panic!("Handle bad leaf count");
    }

    let mut o: Vec<u8> = vec![0; (num_nodes(leaves) - leaves) * HASHSIZE];
    o.append(&mut values.to_vec());

    let mut i = o.len();
    let mut j = o.len() - values.len();

    while i >= MERKLE_HASH_CHUNCK {
        i -= MERKLE_HASH_CHUNCK;
        let hash = hash(&o[i..i + MERKLE_HASH_CHUNCK]);

        j -= HASHSIZE;
        o[j..j + HASHSIZE].copy_from_slice(&hash);
    }

    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(many: Vec<&[u8]>) -> Vec<u8> {
        let mut all = vec![];
        for one in many {
            all.extend_from_slice(&mut one.clone())
        }
        all
    }

    #[test]
    fn merkleize_4_leaves() {
        let data1 = hash(&int_to_bytes32(1));
        let data2 = hash(&int_to_bytes32(2));
        let data3 = hash(&int_to_bytes32(3));
        let data4 = hash(&int_to_bytes32(4));

        let data = join(vec![&data1, &data2, &data3, &data4]);

        let cache = merkleize(&data);

        let hash_12 = {
            let mut joined = vec![];
            joined.append(&mut data1.clone());
            joined.append(&mut data2.clone());
            hash(&joined)
        };
        let hash_34 = {
            let mut joined = vec![];
            joined.append(&mut data3.clone());
            joined.append(&mut data4.clone());
            hash(&joined)
        };
        let hash_hash12_hash_34 = {
            let mut joined = vec![];
            joined.append(&mut hash_12.clone());
            joined.append(&mut hash_34.clone());
            hash(&joined)
        };

        for (i, chunk) in cache.chunks(HASHSIZE).enumerate().rev() {
            let expected = match i {
                0 => hash_hash12_hash_34.clone(),
                1 => hash_12.clone(),
                2 => hash_34.clone(),
                3 => data1.clone(),
                4 => data2.clone(),
                5 => data3.clone(),
                6 => data4.clone(),
                _ => vec![],
            };

            assert_eq!(chunk, &expected[..], "failed at {}", i);
        }
    }
}
