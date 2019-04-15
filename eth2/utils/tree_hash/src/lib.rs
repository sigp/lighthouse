use hashing::hash;
use int_to_bytes::int_to_bytes32;
use std::fmt::Debug;
use std::iter::Iterator;
use std::ops::Range;

mod cached_tree_hash;
mod impls;
mod resize;

pub use cached_tree_hash::TreeHashCache;

pub const BYTES_PER_CHUNK: usize = 32;
pub const HASHSIZE: usize = 32;
pub const MERKLE_HASH_CHUNCK: usize = 2 * BYTES_PER_CHUNK;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    ShouldNotProduceBTreeOverlay,
    NoFirstNode,
    NoBytesForRoot,
    UnableToObtainSlices,
    UnableToGrowMerkleTree,
    UnableToShrinkMerkleTree,
    BytesAreNotEvenChunks(usize),
    NoModifiedFieldForChunk(usize),
    NoBytesForChunk(usize),
}

#[derive(Debug, PartialEq, Clone)]
pub enum ItemType {
    Basic,
    List,
    Composite,
}

// TODO: remove debug requirement.
pub trait CachedTreeHash<Item>: Debug {
    fn item_type() -> ItemType;

    fn build_tree_hash_cache(&self) -> Result<TreeHashCache, Error>;

    /// Return the number of bytes when this element is encoded as raw SSZ _without_ length
    /// prefixes.
    fn num_bytes(&self) -> usize;

    fn offsets(&self) -> Result<Vec<usize>, Error>;

    fn num_child_nodes(&self) -> usize;

    fn packed_encoding(&self) -> Vec<u8>;

    fn packing_factor() -> usize;

    fn cached_hash_tree_root(
        &self,
        other: &Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error>;
}

fn children(parent: usize) -> (usize, usize) {
    ((2 * parent + 1), (2 * parent + 2))
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

fn node_range_to_byte_range(node_range: &Range<usize>) -> Range<usize> {
    node_range.start * HASHSIZE..node_range.end * HASHSIZE
}

#[derive(Debug)]
pub struct BTreeOverlay {
    num_internal_nodes: usize,
    pub num_leaf_nodes: usize,
    first_node: usize,
    next_node: usize,
    offsets: Vec<usize>,
}

impl BTreeOverlay {
    pub fn new<T>(item: &T, initial_offset: usize) -> Result<Self, Error>
    where
        T: CachedTreeHash<T>,
    {
        Self::from_lengths(initial_offset, item.offsets()?)
    }

    fn from_lengths(offset: usize, mut lengths: Vec<usize>) -> Result<Self, Error> {
        // Extend it to the next power-of-two, if it is not already.
        let num_leaf_nodes = if lengths.len().is_power_of_two() {
            lengths.len()
        } else {
            let num_leaf_nodes = lengths.len().next_power_of_two();
            lengths.resize(num_leaf_nodes, 1);
            num_leaf_nodes
        };

        let num_nodes = num_nodes(num_leaf_nodes);
        let num_internal_nodes = num_nodes - num_leaf_nodes;

        let mut offsets = Vec::with_capacity(num_nodes);
        offsets.append(&mut (offset..offset + num_internal_nodes).collect());

        let mut next_node = num_internal_nodes + offset;
        for i in 0..num_leaf_nodes {
            offsets.push(next_node);
            next_node += lengths[i];
        }

        Ok(Self {
            num_internal_nodes,
            num_leaf_nodes,
            offsets,
            first_node: offset,
            next_node,
        })
    }

    pub fn root(&self) -> usize {
        self.first_node
    }

    pub fn height(&self) -> usize {
        self.num_leaf_nodes.trailing_zeros() as usize
    }

    pub fn chunk_range(&self) -> Range<usize> {
        self.first_node..self.next_node
    }

    pub fn total_chunks(&self) -> usize {
        self.next_node - self.first_node
    }

    pub fn total_nodes(&self) -> usize {
        self.num_internal_nodes + self.num_leaf_nodes
    }

    pub fn first_leaf_node(&self) -> Result<usize, Error> {
        self.offsets
            .get(self.num_internal_nodes)
            .cloned()
            .ok_or_else(|| Error::NoFirstNode)
    }

    pub fn next_node(&self) -> usize {
        self.next_node
    }

    /// Returns an iterator visiting each internal node, providing the left and right child chunks
    /// for the node.
    pub fn iter_internal_nodes<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (&'a usize, (&'a usize, &'a usize))> {
        let internal_nodes = &self.offsets[0..self.num_internal_nodes];

        internal_nodes.iter().enumerate().map(move |(i, parent)| {
            let children = children(i);
            (
                parent,
                (&self.offsets[children.0], &self.offsets[children.1]),
            )
        })
    }

    /// Returns an iterator visiting each leaf node, providing the chunk for that node.
    pub fn iter_leaf_nodes<'a>(&'a self) -> impl DoubleEndedIterator<Item = &'a usize> {
        let leaf_nodes = &self.offsets[self.num_internal_nodes..];

        leaf_nodes.iter()
    }
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

/// Rounds up
fn num_sanitized_leaves(num_bytes: usize) -> usize {
    let leaves = (num_bytes + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

fn num_bytes(num_leaves: usize) -> usize {
    num_leaves * HASHSIZE
}
