use promise_cache::{PromiseCache, Protect};
use types::{BeaconState, EthSpec, Hash256};

#[derive(Default)]
pub struct HttpProtector;

impl Protect<Hash256> for HttpProtector {
    type SortKey = Hash256;

    /// We don't care too much about preventing evictions of particular states here. All the states
    /// in this cache should be different from the head state.
    fn protect_from_eviction(&self, _: &Hash256) -> bool {
        false
    }

    /// Evict in arbitrary (hash) order.
    fn sort_key(&self, k: &Hash256) -> Self::SortKey {
        *k
    }
}

pub type HttpStateCache<E> = PromiseCache<Hash256, BeaconState<E>, HttpProtector>;
