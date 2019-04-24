use super::*;
use hashing::hash;
use int_to_bytes::int_to_bytes32;
use std::ops::Range;

pub mod btree_overlay;
pub mod impls;
pub mod resize;
pub mod tree_hash_cache;

pub use btree_overlay::BTreeOverlay;
pub use tree_hash_cache::TreeHashCache;

#[derive(Debug, PartialEq)]
pub struct CachedTreeHasher {
    cache: TreeHashCache,
}

impl CachedTreeHasher {
    pub fn new<T>(item: &T) -> Result<Self, Error>
    where
        T: CachedTreeHash<T>,
    {
        Ok(Self {
            cache: TreeHashCache::new(item, 0)?,
        })
    }

    pub fn update<T>(&mut self, item: &T) -> Result<(), Error>
    where
        T: CachedTreeHash<T>,
    {
        // Reset the per-hash counters.
        self.cache.chunk_index = 0;
        self.cache.overlay_index = 0;

        // Reset the "modified" flags for the cache.
        self.cache.reset_modifications();

        // Update the cache with the (maybe) changed object.
        item.update_tree_hash_cache(&mut self.cache)?;

        Ok(())
    }

    pub fn tree_hash_root(&self) -> Result<Vec<u8>, Error> {
        // Return the root of the cache -- the merkle root.
        Ok(self.cache.root()?.to_vec())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    ShouldNotProduceBTreeOverlay,
    NoFirstNode,
    NoBytesForRoot,
    UnableToObtainSlices,
    UnableToGrowMerkleTree,
    UnableToShrinkMerkleTree,
    TreeCannotHaveZeroNodes,
    ShouldNeverBePacked(TreeHashType),
    BytesAreNotEvenChunks(usize),
    NoModifiedFieldForChunk(usize),
    NoBytesForChunk(usize),
    NoOverlayForIndex(usize),
    NotLeafNode(usize),
}

pub trait CachedTreeHash<Item>: TreeHash {
    fn tree_hash_cache_overlay(
        &self,
        chunk_offset: usize,
        depth: usize,
    ) -> Result<BTreeOverlay, Error>;

    fn num_tree_hash_cache_chunks(&self) -> usize;

    fn new_tree_hash_cache(&self, depth: usize) -> Result<TreeHashCache, Error>;

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error>;
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

fn node_range_to_byte_range(node_range: &Range<usize>) -> Range<usize> {
    node_range.start * HASHSIZE..node_range.end * HASHSIZE
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

fn pad_for_leaf_count(num_leaves: usize, bytes: &mut Vec<u8>) {
    let required_leaves = num_leaves.next_power_of_two();

    bytes.resize(
        bytes.len() + (required_leaves - num_leaves) * BYTES_PER_CHUNK,
        0,
    );
}

fn last_leaf_needs_padding(num_bytes: usize) -> bool {
    num_bytes % HASHSIZE != 0
}

/// Rounds up
fn num_unsanitized_leaves(num_bytes: usize) -> usize {
    (num_bytes + HASHSIZE - 1) / HASHSIZE
}

fn num_bytes(num_leaves: usize) -> usize {
    num_leaves * HASHSIZE
}
