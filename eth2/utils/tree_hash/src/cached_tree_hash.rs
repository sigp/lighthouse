use super::*;
use hashing::hash;
use int_to_bytes::int_to_bytes32;
use std::ops::Range;

pub mod btree_overlay;
pub mod impls;
pub mod resize;

pub use btree_overlay::BTreeOverlay;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    ShouldNotProduceBTreeOverlay,
    NoFirstNode,
    NoBytesForRoot,
    UnableToObtainSlices,
    UnableToGrowMerkleTree,
    UnableToShrinkMerkleTree,
    ShouldNeverBePacked(ItemType),
    BytesAreNotEvenChunks(usize),
    NoModifiedFieldForChunk(usize),
    NoBytesForChunk(usize),
}

pub trait CachedTreeHash<T>: CachedTreeHashSubTree<T> + Sized {
    fn update_internal_tree_hash_cache(self, old: T) -> Result<(Self, Self), Error>;

    fn cached_tree_hash_root(&self) -> Option<Vec<u8>>;

    fn clone_without_tree_hash_cache(&self) -> Self;
}

pub trait CachedTreeHashSubTree<Item> {
    fn item_type() -> ItemType;

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error>;

    fn packed_encoding(&self) -> Result<Vec<u8>, Error>;

    fn packing_factor() -> usize;

    fn new_cache(&self) -> Result<TreeHashCache, Error>;

    fn update_cache(
        &self,
        other: &Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error>;
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

#[derive(Debug, PartialEq, Clone)]
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
    pub fn new<T>(item: &T) -> Result<Self, Error>
    where
        T: CachedTreeHashSubTree<T>,
    {
        item.new_cache()
    }

    pub fn from_elems(cache: Vec<u8>, chunk_modified: Vec<bool>) -> Self {
        Self {
            cache,
            chunk_modified,
        }
    }

    pub fn from_leaves_and_subtrees<T>(
        item: &T,
        leaves_and_subtrees: Vec<Self>,
    ) -> Result<Self, Error>
    where
        T: CachedTreeHashSubTree<T>,
    {
        let offset_handler = BTreeOverlay::new(item, 0)?;

        // Note how many leaves were provided. If is not a power-of-two, we'll need to pad it out
        // later.
        let num_provided_leaf_nodes = leaves_and_subtrees.len();

        // Allocate enough bytes to store the internal nodes and the leaves and subtrees, then fill
        // all the to-be-built internal nodes with zeros and append the leaves and subtrees.
        let internal_node_bytes = offset_handler.num_internal_nodes * BYTES_PER_CHUNK;
        let leaves_and_subtrees_bytes = leaves_and_subtrees
            .iter()
            .fold(0, |acc, t| acc + t.bytes_len());
        let mut cache = Vec::with_capacity(leaves_and_subtrees_bytes + internal_node_bytes);
        cache.resize(internal_node_bytes, 0);

        // Allocate enough bytes to store all the leaves.
        let mut leaves = Vec::with_capacity(offset_handler.num_leaf_nodes * HASHSIZE);

        // Iterate through all of the leaves/subtrees, adding their root as a leaf node and then
        // concatenating their merkle trees.
        for t in leaves_and_subtrees {
            leaves.append(&mut t.root().ok_or_else(|| Error::NoBytesForRoot)?.to_vec());
            cache.append(&mut t.into_merkle_tree());
        }

        // Pad the leaves to an even power-of-two, using zeros.
        pad_for_leaf_count(num_provided_leaf_nodes, &mut cache);

        // Merkleize the leaves, then split the leaf nodes off them. Then, replace all-zeros
        // internal nodes created earlier with the internal nodes generated by `merkleize`.
        let mut merkleized = merkleize(leaves);
        merkleized.split_off(internal_node_bytes);
        cache.splice(0..internal_node_bytes, merkleized);

        Ok(Self {
            chunk_modified: vec![false; cache.len() / BYTES_PER_CHUNK],
            cache,
        })
    }

    pub fn from_bytes(bytes: Vec<u8>, initial_modified_state: bool) -> Result<Self, Error> {
        if bytes.len() % BYTES_PER_CHUNK > 0 {
            return Err(Error::BytesAreNotEvenChunks(bytes.len()));
        }

        Ok(Self {
            chunk_modified: vec![initial_modified_state; bytes.len() / BYTES_PER_CHUNK],
            cache: bytes,
        })
    }

    pub fn bytes_len(&self) -> usize {
        self.cache.len()
    }

    pub fn root(&self) -> Option<&[u8]> {
        self.cache.get(0..HASHSIZE)
    }

    pub fn splice(&mut self, chunk_range: Range<usize>, replace_with: Self) {
        let (bytes, bools) = replace_with.into_components();

        // Update the `chunk_modified` vec, marking all spliced-in nodes as changed.
        self.chunk_modified.splice(chunk_range.clone(), bools);
        self.cache
            .splice(node_range_to_byte_range(&chunk_range), bytes);
    }

    pub fn maybe_update_chunk(&mut self, chunk: usize, to: &[u8]) -> Result<(), Error> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        if !self.chunk_equals(chunk, to)? {
            self.cache
                .get_mut(start..end)
                .ok_or_else(|| Error::NoModifiedFieldForChunk(chunk))?
                .copy_from_slice(to);
            self.chunk_modified[chunk] = true;
        }

        Ok(())
    }

    pub fn slices(&self, chunk_range: Range<usize>) -> Option<(&[u8], &[bool])> {
        Some((
            self.cache.get(node_range_to_byte_range(&chunk_range))?,
            self.chunk_modified.get(chunk_range)?,
        ))
    }

    pub fn modify_chunk(&mut self, chunk: usize, to: &[u8]) -> Result<(), Error> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        self.cache
            .get_mut(start..end)
            .ok_or_else(|| Error::NoBytesForChunk(chunk))?
            .copy_from_slice(to);

        self.chunk_modified[chunk] = true;

        Ok(())
    }

    pub fn get_chunk(&self, chunk: usize) -> Result<&[u8], Error> {
        let start = chunk * BYTES_PER_CHUNK;
        let end = start + BYTES_PER_CHUNK;

        Ok(self
            .cache
            .get(start..end)
            .ok_or_else(|| Error::NoModifiedFieldForChunk(chunk))?)
    }

    pub fn chunk_equals(&mut self, chunk: usize, other: &[u8]) -> Result<bool, Error> {
        Ok(self.get_chunk(chunk)? == other)
    }

    pub fn changed(&self, chunk: usize) -> Result<bool, Error> {
        self.chunk_modified
            .get(chunk)
            .cloned()
            .ok_or_else(|| Error::NoModifiedFieldForChunk(chunk))
    }

    pub fn either_modified(&self, children: (&usize, &usize)) -> Result<bool, Error> {
        Ok(self.changed(*children.0)? | self.changed(*children.1)?)
    }

    pub fn hash_children(&self, children: (&usize, &usize)) -> Result<Vec<u8>, Error> {
        let mut child_bytes = Vec::with_capacity(BYTES_PER_CHUNK * 2);
        child_bytes.append(&mut self.get_chunk(*children.0)?.to_vec());
        child_bytes.append(&mut self.get_chunk(*children.1)?.to_vec());

        Ok(hash(&child_bytes))
    }

    pub fn mix_in_length(&self, chunk: usize, length: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(2 * BYTES_PER_CHUNK);

        bytes.append(&mut self.get_chunk(chunk)?.to_vec());
        bytes.append(&mut int_to_bytes32(length as u64));

        Ok(hash(&bytes))
    }

    pub fn into_merkle_tree(self) -> Vec<u8> {
        self.cache
    }

    pub fn into_components(self) -> (Vec<u8>, Vec<bool>) {
        (self.cache, self.chunk_modified)
    }
}
