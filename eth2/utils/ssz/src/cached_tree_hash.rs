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

    /*
    #[test]
    fn container() {
        let data1 = hash(&vec![1; 32]);
        let data2 = hash(&vec![2; 32]);
        let data3 = hash(&vec![3; 32]);
        let data4 = hash(&vec![4; 32]);

        let data = join(vec![&data1, &data2, &data3, &data4]);

        let cache = cache_builder(&data).unwrap();
    }
    */
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
/*

/// Get merkle root of some hashed values - the input leaf nodes is expected to already be hashed
/// Outputs a `Vec<u8>` byte array of the merkle root given a set of leaf node values.
pub fn cache_builder(values: &[u8]) -> Option<Vec<u8>> {
    let leaves = values.len() / HASHSIZE;

    if leaves == 0 || !leaves.is_power_of_two() {
        return None;
    }

    let mut o: Vec<u8> = vec![0; (num_nodes(leaves) - leaves) * HASHSIZE];
    o.append(&mut values.to_vec());

    let mut i = o.len();
    let mut j = o.len() - values.len();

    while i >= MERKLE_HASH_CHUNCK {
        i -= MERKLE_HASH_CHUNCK;
        let hash = hash(&o[i..i + MERKLE_HASH_CHUNCK]);

        j -= HASHSIZE;
        o.get_mut(j..j + HASHSIZE)?.copy_from_slice(&hash);
    }

    return Some(o);
}

fn parent(child: usize) -> usize {
    (child - 1) / 2
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

pub struct Outer {
    pub a: u64,
    pub b: u64,
    pub inner: Inner,
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

    /*
    #[test]
    fn container() {
        let data1 = hash(&vec![1; 32]);
        let data2 = hash(&vec![2; 32]);
        let data3 = hash(&vec![3; 32]);
        let data4 = hash(&vec![4; 32]);

        let data = join(vec![&data1, &data2, &data3, &data4]);

        let cache = cache_builder(&data).unwrap();
    }
    */
#[test]
fn can_build_cache() {
let data1 = hash(&vec![1; 32]);
let data2 = hash(&vec![2; 32]);
let data3 = hash(&vec![3; 32]);
let data4 = hash(&vec![4; 32]);

let data = join(vec![&data1, &data2, &data3, &data4]);

let cache = cache_builder(&data).unwrap();

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

/*
pub trait TreeHash {
    fn hash_tree_root(&self) -> Vec<u8>;
}

/// Returns a 32 byte hash of 'list' - a vector of byte vectors.
/// Note that this will consume 'list'.
pub fn merkle_hash(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // flatten list
    let mut chunkz = list_to_blob(list);

    // get data_len as bytes. It will hashed will the merkle root
    let mut datalen = list.len().to_le_bytes().to_vec();
    zpad(&mut datalen, 32);

    // merklelize
    while chunkz.len() > HASHSIZE {
        let mut new_chunkz: Vec<u8> = Vec::new();

        for two_chunks in chunkz.chunks(BYTES_PER_CHUNK * 2) {
            // Hash two chuncks together
            new_chunkz.append(&mut hash(two_chunks));
        }

        chunkz = new_chunkz;
    }

    chunkz.append(&mut datalen);
    hash(&chunkz)
}

fn list_to_blob(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // pack - fit as many many items per chunk as we can and then
    // right pad to BYTES_PER_CHUNCK
    let (items_per_chunk, chunk_count) = if list.is_empty() {
        (1, 1)
    } else {
        let items_per_chunk = BYTES_PER_CHUNK / list[0].len();
        let chunk_count = list.len() / items_per_chunk;
        (items_per_chunk, chunk_count)
    };

    let mut chunkz = Vec::new();
    if list.is_empty() {
        // handle and empty list
        chunkz.append(&mut vec![0; BYTES_PER_CHUNK * 2]);
    } else if list[0].len() <= BYTES_PER_CHUNK {
        // just create a blob here; we'll divide into
        // chunked slices when we merklize
        let mut chunk = Vec::with_capacity(BYTES_PER_CHUNK);
        let mut item_count_in_chunk = 0;
        chunkz.reserve(chunk_count * BYTES_PER_CHUNK);
        for item in list.iter_mut() {
            item_count_in_chunk += 1;
            chunk.append(item);

            // completed chunk?
            if item_count_in_chunk == items_per_chunk {
                zpad(&mut chunk, BYTES_PER_CHUNK);
                chunkz.append(&mut chunk);
                item_count_in_chunk = 0;
            }
        }

        // left-over uncompleted chunk?
        if item_count_in_chunk != 0 {
            zpad(&mut chunk, BYTES_PER_CHUNK);
            chunkz.append(&mut chunk);
        }
    }

    // extend the number of chunks to a power of two if necessary
    if !chunk_count.is_power_of_two() {
        let zero_chunks_count = chunk_count.next_power_of_two() - chunk_count;
        chunkz.append(&mut vec![0; zero_chunks_count * BYTES_PER_CHUNK]);
    }

    chunkz
}

/// right pads with zeros making 'bytes' 'size' in length
fn zpad(bytes: &mut Vec<u8>, size: usize) {
    if bytes.len() < size {
        bytes.resize(size, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_hash() {
        let data1 = vec![1; 32];
        let data2 = vec![2; 32];
        let data3 = vec![3; 32];
        let mut list = vec![data1, data2, data3];
        let result = merkle_hash(&mut list);

        //note: should test againt a known test hash value
        assert_eq!(HASHSIZE, result.len());
    }
}
*/
*/
