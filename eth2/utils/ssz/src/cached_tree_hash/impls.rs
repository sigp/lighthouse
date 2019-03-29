use super::*;
use crate::{ssz_encode, Encodable};

impl CachedTreeHash for u64 {
    type Item = Self;

    fn leaves_and_subtrees(&self) -> Vec<u8> {
        merkleize(ssz_encode(self))
    }

    fn num_bytes(&self) -> usize {
        8
    }

    fn offsets(&self) -> Result<Vec<usize>, Error> {
        Err(Error::ShouldNotProduceOffsetHandler)
    }

    fn num_child_nodes(&self) -> usize {
        0
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        if self != other {
            let leaf = merkleize(ssz_encode(self));
            cache.modify_chunk(chunk, &leaf)?;
        }

        Ok(chunk + 1)
    }
}

/*
impl<T> CachedTreeHash for Vec<T>
where
    T: CachedTreeHash + Encodable,
{
    type Item = Self;

    fn build_cache_bytes(&self) -> Vec<u8> {
        let num_packed_bytes = self.num_bytes();
        let num_leaves = num_sanitized_leaves(num_packed_bytes);

        let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

        for item in self {
            packed.append(&mut ssz_encode(item));
        }

        let packed = sanitise_bytes(packed);

        merkleize(packed)
    }

    fn num_bytes(&self) -> usize {
        self.iter().fold(0, |acc, item| acc + item.num_bytes())
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self::Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Option<usize> {
        let num_packed_bytes = self.num_bytes();
        let num_leaves = num_sanitized_leaves(num_packed_bytes);

        if num_leaves != num_sanitized_leaves(other.num_bytes()) {
            panic!("Need to handle a change in leaf count");
        }

        let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

        // TODO: try and avoid fully encoding the whole list
        for item in self {
            packed.append(&mut ssz_encode(item));
        }

        let packed = sanitise_bytes(packed);

        let num_nodes = num_nodes(num_leaves);
        let num_internal_nodes = num_nodes - num_leaves;

        {
            let mut chunk = chunk + num_internal_nodes;
            for new_chunk_bytes in packed.chunks(HASHSIZE) {
                cache.maybe_update_chunk(chunk, new_chunk_bytes)?;
                chunk += 1;
            }
        }

        // Iterate backwards through the internal nodes, rehashing any node where it's children
        // have changed.
        for chunk in (chunk..chunk + num_internal_nodes).into_iter().rev() {
            if cache.children_modified(chunk)? {
                cache.modify_chunk(chunk, &cache.hash_children(chunk)?)?;
            }
        }

        Some(chunk + num_nodes)
    }
}
*/
