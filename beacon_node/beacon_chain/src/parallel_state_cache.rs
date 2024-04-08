use promise_cache::{PromiseCache, Protect};
use types::{BeaconState, Hash256};

#[derive(Debug, Default)]
pub struct ParallelStateProtector;

impl Protect<Hash256> for ParallelStateProtector {
    type SortKey = usize;

    /// Evict in arbitrary (hashmap) order by using the same key for every value.
    fn sort_key(&self, _: &Hash256) -> Self::SortKey {
        0
    }

    /// We don't care too much about preventing evictions of particular states here. All the states
    /// in this cache should be different from the head state.
    fn protect_from_eviction(&self, _: &Hash256) -> bool {
        false
    }
}

pub type ParallelStateCache<E> = PromiseCache<Hash256, BeaconState<E>, ParallelStateProtector>;
