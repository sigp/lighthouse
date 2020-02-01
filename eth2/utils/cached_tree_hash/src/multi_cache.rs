use crate::{int_log, CachedTreeHash, Error, Hash256, TreeHashCache, VecArena};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::Unsigned, VariableList};
use tree_hash::mix_in_length;

/// Multi-level tree hash cache.
///
/// Suitable for lists/vectors/containers holding values which themselves have caches.
///
/// Note: this cache could be made composable by replacing the hardcoded `Vec<TreeHashCache>` with
/// `Vec<C>`, allowing arbitrary nesting, but for now we stick to 2-level nesting because that's all
/// we need.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct MultiTreeHashCache {
    list_cache: TreeHashCache,
    value_caches: Vec<TreeHashCache>,
}

impl<T, N> CachedTreeHash<MultiTreeHashCache> for VariableList<T, N>
where
    T: CachedTreeHash<TreeHashCache>,
    N: Unsigned,
{
    fn new_tree_hash_cache(&self, arena: &mut VecArena) -> MultiTreeHashCache {
        MultiTreeHashCache {
            // TODO: here we use `self.len()` for the leaf count. This will only work for composite
            // values.
            list_cache: TreeHashCache::new(arena, int_log(N::to_usize()), self.len()),
            value_caches: vec![],
        }
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut VecArena,
        cache: &mut MultiTreeHashCache,
    ) -> Result<Hash256, Error> {
        if self.len() < cache.value_caches.len() {
            return Err(Error::CannotShrink);
        }

        // Resize the value caches to the size of the list.
        self.iter()
            .skip(cache.value_caches.len())
            .for_each(|value| cache.value_caches.push(value.new_tree_hash_cache(arena)));

        // Update all individual value caches.
        let leaves = self
            .iter()
            .zip(cache.value_caches.iter_mut())
            .map(|(value, cache)| {
                value.recalculate_tree_hash_root(arena, cache).map(|_| ())?;
                Ok(cache.root(arena).to_fixed_bytes())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let list_root = cache
            .list_cache
            .recalculate_merkle_root(arena, leaves.into_iter())?;

        Ok(Hash256::from_slice(&mix_in_length(
            list_root.as_bytes(),
            self.len(),
        )))
    }
}
