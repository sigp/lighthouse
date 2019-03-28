use hashing::hash;

mod impls;
mod tests;

const BYTES_PER_CHUNK: usize = 32;
const HASHSIZE: usize = 32;
const MERKLE_HASH_CHUNCK: usize = 2 * BYTES_PER_CHUNK;

pub trait CachedTreeHash {
    type Item: CachedTreeHash;

    fn build_cache_bytes(&self) -> Vec<u8>;

    /// Return the number of bytes when this element is encoded as raw SSZ _without_ length
    /// prefixes.
    fn num_bytes(&self) -> usize;

    fn cached_hash_tree_root(
        &self,
        other: &Self::Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Option<usize>;
}

pub struct TreeHashCache {
    cache: Vec<u8>,
    chunk_modified: Vec<bool>,
}

impl Into<Vec<u8>> for TreeHashCache {
    fn into(self) -> Vec<u8> {
        self.cache
    }
}

impl TreeHashCache {
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() % BYTES_PER_CHUNK > 0 {
            return None;
        }

        Some(Self {
            chunk_modified: vec![false; bytes.len() / BYTES_PER_CHUNK],
            cache: bytes,
        })
    }

    pub fn maybe_update_chunk(&mut self, chunk: usize, to: &[u8]) -> Option<()> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        if !self.chunk_equals(chunk, to)? {
            self.cache.get_mut(start..end)?.copy_from_slice(to);
            self.chunk_modified[chunk] = true;
        }

        Some(())
    }

    pub fn modify_chunk(&mut self, chunk: usize, to: &[u8]) -> Option<()> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        self.cache.get_mut(start..end)?.copy_from_slice(to);

        self.chunk_modified[chunk] = true;

        Some(())
    }

    pub fn chunk_equals(&mut self, chunk: usize, other: &[u8]) -> Option<bool> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        Some(self.cache.get(start..end)? == other)
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
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

/// Split `values` into a power-of-two, identical-length chunks (padding with `0`) and merkleize
/// them, returning the entire merkle tree.
///
/// The root hash is `merkleize(values)[0..BYTES_PER_CHUNK]`.
pub fn merkleize(values: Vec<u8>) -> Vec<u8> {
    let values = sanitise_bytes(values);

    let leaves = values.len() / HASHSIZE;

    if leaves == 0 {
        panic!("No full leaves");
    }

    if !leaves.is_power_of_two() {
        panic!("leaves is not power of two");
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

pub fn sanitise_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    let present_leaves = num_unsanitized_leaves(bytes.len());
    let required_leaves = present_leaves.next_power_of_two();

    if (present_leaves != required_leaves) | last_leaf_needs_padding(bytes.len()) {
        bytes.resize(num_bytes(required_leaves), 0);
    }

    bytes
}

fn last_leaf_needs_padding(num_bytes: usize) -> bool {
    num_bytes % HASHSIZE != 0
}

/// Rounds up
fn num_unsanitized_leaves(num_bytes: usize) -> usize {
    (num_bytes + HASHSIZE - 1) / HASHSIZE
}

/// Rounds up
fn num_sanitized_leaves(num_bytes: usize) -> usize {
    let leaves = (num_bytes + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

fn num_bytes(num_leaves: usize) -> usize {
    num_leaves * HASHSIZE
}
