use super::*;
use crate::{ssz_encode, Encodable};

impl CachedTreeHash for u64 {
    type Item = Self;

    fn item_type() -> ItemType {
        ItemType::Basic
    }

    fn build_tree_hash_cache(&self) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(merkleize(ssz_encode(self)))?)
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

    fn packed_encoding(&self) -> Vec<u8> {
        ssz_encode(self)
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

impl<T> CachedTreeHash for Vec<T>
where
    T: CachedTreeHash,
{
    type Item = Self;

    fn item_type() -> ItemType {
        ItemType::List
    }

    fn build_tree_hash_cache(&self) -> Result<TreeHashCache, Error> {
        match T::item_type() {
            ItemType::Basic => {
                let num_packed_bytes = self.num_bytes();
                let num_leaves = num_sanitized_leaves(num_packed_bytes);

                let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

                for item in self {
                    packed.append(&mut item.packed_encoding());
                }

                let packed = sanitise_bytes(packed);

                TreeHashCache::from_bytes(merkleize(packed))
            }
            ItemType::Composite | ItemType::List => {
                let subtrees = self
                    .iter()
                    .map(|item| TreeHashCache::new(item))
                    .collect::<Result<Vec<TreeHashCache>, _>>()?;

                TreeHashCache::from_leaves_and_subtrees(self, subtrees)
            }
        }
    }

    fn offsets(&self) -> Result<Vec<usize>, Error> {
        let mut offsets = vec![];

        for item in self {
            offsets.push(item.offsets()?.iter().sum())
        }

        Ok(offsets)
    }

    fn num_child_nodes(&self) -> usize {
        // TODO
        42
    }

    fn num_bytes(&self) -> usize {
        self.iter().fold(0, |acc, item| acc + item.num_bytes())
    }

    fn packed_encoding(&self) -> Vec<u8> {
        panic!("List should never be packed")
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self::Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        /*
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
        */
        // TODO
        Ok(42)
    }
}

/*
fn get_packed_leaves<T>(vec: Vec<T>) -> Vec<u8>
where
    T: Encodable,
{
    //
}
*/
