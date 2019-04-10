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

    fn packing_factor() -> usize {
        32 / 8
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
            ItemType::Basic => TreeHashCache::from_bytes(merkleize(get_packed_leaves(self))),
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
        let offsets = match T::item_type() {
            ItemType::Basic => vec![1; self.len() / T::packing_factor()],
            ItemType::Composite | ItemType::List => {
                let mut offsets = vec![];

                for item in self {
                    offsets.push(item.offsets()?.iter().sum())
                }

                offsets
            }
        };

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

    fn packing_factor() -> usize {
        1
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self::Item,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = OffsetHandler::new(self, chunk)?;

        match T::item_type() {
            ItemType::Basic => {
                let leaves = get_packed_leaves(self);

                for (i, chunk) in offset_handler.iter_leaf_nodes().enumerate() {
                    if let Some(latest) = leaves.get(i * HASHSIZE..(i + 1) * HASHSIZE) {
                        if !cache.chunk_equals(*chunk, latest)? {
                            dbg!(chunk);
                            cache.set_changed(*chunk, true)?;
                        }
                    }
                }
                let first_leaf_chunk = offset_handler.first_leaf_node()?;
                cache.chunk_splice(first_leaf_chunk..offset_handler.next_node, leaves);
            }
            _ => panic!("not implemented"),
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node())
    }
}

fn get_packed_leaves<T>(vec: &Vec<T>) -> Vec<u8>
where
    T: CachedTreeHash,
{
    let num_packed_bytes = vec.num_bytes();
    let num_leaves = num_sanitized_leaves(num_packed_bytes);

    let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

    for item in vec {
        packed.append(&mut item.packed_encoding());
    }

    sanitise_bytes(packed)
}
