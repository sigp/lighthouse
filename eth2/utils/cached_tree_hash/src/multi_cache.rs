use crate::{int_log, CachedTreeHash, Error, Hash256, TreeHashCache};
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
    fn new_tree_hash_cache() -> MultiTreeHashCache {
        MultiTreeHashCache {
            list_cache: TreeHashCache::new(int_log(N::to_usize())),
            value_caches: vec![],
        }
    }

    fn recalculate_tree_hash_root(&self, cache: &mut MultiTreeHashCache) -> Result<Hash256, Error> {
        if self.len() < cache.value_caches.len() {
            return Err(Error::CannotShrink);
        }

        // Resize the value caches to the size of the list.
        cache
            .value_caches
            .resize(self.len(), T::new_tree_hash_cache());

        // Update all individual value caches.
        self.iter()
            .zip(cache.value_caches.iter_mut())
            .try_for_each(|(value, cache)| value.recalculate_tree_hash_root(cache).map(|_| ()))?;

        // Pipe the value roots into the list cache, then mix in the length.
        // Note: it's possible to avoid this 2nd iteration (or an allocation) by using
        // `itertools::process_results`, but it requires removing the `ExactSizeIterator`
        // bound from `recalculate_merkle_root`, and only saves about 5% in benchmarks.
        let list_root = cache.list_cache.recalculate_merkle_root(
            cache
                .value_caches
                .iter()
                .map(|value_cache| value_cache.root().to_fixed_bytes()),
        )?;

        Ok(Hash256::from_slice(&mix_in_length(
            list_root.as_bytes(),
            self.len(),
        )))
    }
}
