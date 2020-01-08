use crate::checkpoint::CheckPoint;
use crate::metrics;
use parking_lot::RwLock;
use std::borrow::Cow;
use types::{BeaconBlock, BeaconState, EthSpec, Hash256};

const CACHE_SIZE: usize = 4;

struct Inner<T: EthSpec> {
    oldest: usize,
    limit: usize,
    checkpoints: Vec<CheckPoint<T>>,
}

impl<T: EthSpec> Default for Inner<T> {
    fn default() -> Self {
        Self {
            oldest: 0,
            limit: CACHE_SIZE,
            checkpoints: vec![],
        }
    }
}

pub struct CheckPointCache<T: EthSpec> {
    inner: RwLock<Inner<T>>,
}

impl<T: EthSpec> Default for CheckPointCache<T> {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
        }
    }
}

impl<T: EthSpec> CheckPointCache<T> {
    pub fn insert(&self, checkpoint: Cow<CheckPoint<T>>) {
        if self
            .inner
            .read()
            .checkpoints
            .iter()
            // This is `O(n)` but whilst `n == 4` it ain't no thing.
            .any(|local| local.beacon_state_root == checkpoint.beacon_state_root)
        {
            // Adding a known checkpoint to the cache should be a no-op.
            return;
        }

        let mut inner = self.inner.write();

        if inner.checkpoints.len() < inner.limit {
            inner.checkpoints.push(checkpoint.into_owned())
        } else {
            let i = inner.oldest; // to satisfy the borrow checker.
            inner.checkpoints[i] = checkpoint.into_owned();
            inner.oldest += 1;
            inner.oldest %= inner.limit;
        }
    }

    pub fn get_state(&self, state_root: &Hash256) -> Option<BeaconState<T>> {
        self.inner
            .read()
            .checkpoints
            .iter()
            // Also `O(n)`.
            .find(|checkpoint| checkpoint.beacon_state_root == *state_root)
            .map(|checkpoint| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_HITS);

                checkpoint.beacon_state.clone()
            })
            .or_else(|| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_MISSES);

                None
            })
    }

    pub fn get_state_only_with_committee_cache(
        &self,
        state_root: &Hash256,
    ) -> Option<BeaconState<T>> {
        self.inner
            .read()
            .checkpoints
            .iter()
            // Also `O(n)`.
            .find(|checkpoint| checkpoint.beacon_state_root == *state_root)
            .map(|checkpoint| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_HITS);

                let mut state = checkpoint.beacon_state.clone_without_caches();
                state.committee_caches = checkpoint.beacon_state.committee_caches.clone();

                state
            })
            .or_else(|| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_MISSES);

                None
            })
    }

    pub fn get_block(&self, block_root: &Hash256) -> Option<BeaconBlock<T>> {
        self.inner
            .read()
            .checkpoints
            .iter()
            // Also `O(n)`.
            .find(|checkpoint| checkpoint.beacon_block_root == *block_root)
            .map(|checkpoint| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_HITS);

                checkpoint.beacon_block.clone()
            })
            .or_else(|| {
                metrics::inc_counter(&metrics::CHECKPOINT_CACHE_MISSES);

                None
            })
    }
}
