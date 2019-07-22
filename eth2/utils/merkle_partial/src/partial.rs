use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use crate::merkle_tree_overlay::MerkleTreeOverlay;
use crate::path::Path;
use crate::tree_arithmetic::zeroed::sibling_index;

use std::marker::PhantomData;
use tree_hash::BYTES_PER_CHUNK;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Partial<T: MerkleTreeOverlay> {
    cache: Cache,
    _phantom: PhantomData<T>,
}

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
impl<T: MerkleTreeOverlay> Partial<T> {
    /// Populates the struct's cache with a `SerializedPartial`.
    pub fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        for (i, index) in partial.indices.iter().enumerate() {
            let chunk = partial.chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK].to_vec();
            self.cache.insert(*index, chunk.clone());
        }

        Ok(())
    }

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    pub fn extract_partial(&self, path: Vec<Path>) -> Result<SerializedPartial> {
        if path.len() == 0 {
            return Err(Error::EmptyPath());
        }

        let node = T::get_node_from_path(path.clone())?;

        let mut visitor = node.get_index();
        let mut indices: Vec<NodeIndex> = vec![visitor];
        let mut chunks: Vec<u8> = self
            .cache
            .get(visitor)
            .ok_or(Error::MissingNode(visitor))?
            .clone();

        while visitor > 0 {
            let sibling = sibling_index(visitor);
            let left = 2 * sibling + 1;
            let right = 2 * sibling + 2;

            if !(indices.contains(&left) && indices.contains(&right)) {
                indices.push(sibling);
                chunks.extend(self.cache.get(sibling).ok_or(Error::MissingNode(sibling))?);
            }

            visitor /= 2;
        }

        Ok(SerializedPartial { indices, chunks })
    }

    /// Returns the bytes representation of the object associated with `path`
    pub fn get_bytes(&self, path: Vec<Path>) -> Result<Vec<u8>> {
        if path.len() == 0 {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<T>(path)?;

        Ok(self.cache.get(index).ok_or(Error::MissingNode(index))?[begin..end].to_vec())
    }

    pub fn set_bytes(&mut self, path: Vec<Path>, bytes: Vec<u8>) -> Result<()> {
        if path.len() == 0 {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<T>(path)?;
        let chunk = self
            .cache
            .get(index)
            .ok_or(Error::ChunkNotLoaded(index))?
            .to_vec()
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, b)| if i >= begin && i < end { bytes[i] } else { b })
            .collect();

        self.cache.insert(index, chunk);
        Ok(())
    }

    /// Determines if the current merkle tree is valid.
    pub fn is_valid(&self, root: Vec<u8>) -> bool {
        self.cache.is_valid(root)
    }

    /// Inserts missing nodes into the merkle tree that can be generated from existing nodes.
    pub fn fill(&mut self) -> Result<()> {
        self.cache.fill()
    }
}

/// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
/// eventually returning the chunk index, beginning offset, and end offset of the associated value.
fn bytes_at_path_helper<T: MerkleTreeOverlay + ?Sized>(
    path: Vec<Path>,
) -> Result<(NodeIndex, usize, usize)> {
    if path.len() == 0 {
        return Err(Error::EmptyPath());
    }

    match T::get_node_from_path(path.clone()) {
        Ok(Node::Composite(c)) => Ok((c.index, 0, 32)),
        Ok(Node::Leaf(Leaf::Length(l))) => Ok((l.index, 0, 32)),
        Ok(Node::Leaf(Leaf::Primitive(l))) => {
            for p in l {
                if p.ident == path.last().unwrap().to_string() {
                    return Ok((p.index, p.offset as usize, (p.offset + p.size) as usize));
                }
            }

            unreachable!()
        }
        _ => Err(Error::InvalidPath(path[0].clone())),
    }
}
