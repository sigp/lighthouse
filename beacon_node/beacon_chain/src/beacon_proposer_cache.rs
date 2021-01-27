use lru::LruCache;
use smallvec::SmallVec;
use std::marker::PhantomData;
use types::{BeaconStateError, Epoch, EthSpec, Fork, Hash256, Slot, Unsigned};

const CACHE_SIZE: usize = 16;
const TYPICAL_SLOTS_PER_EPOCH: usize = 32;

pub struct Proposer {
    pub index: usize,
    pub fork: Fork,
}

pub struct EpochBlockProposers<T> {
    epoch: Epoch,
    fork: Fork,
    proposers: SmallVec<[usize; TYPICAL_SLOTS_PER_EPOCH]>,
    _phantom: PhantomData<T>,
}

pub struct BeaconProposerCache<T> {
    cache: LruCache<(Epoch, Hash256), EpochBlockProposers<T>>,
}

impl<T> Default for BeaconProposerCache<T> {
    fn default() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }
}

impl<T: EthSpec> BeaconProposerCache<T> {
    pub fn get(&mut self, key: (Epoch, Hash256), slot: Slot) -> Option<Proposer> {
        if let Some(cache) = self.cache.get(&key) {
            let epoch = slot.epoch(T::slots_per_epoch());
            if epoch == cache.epoch {
                cache
                    .proposers
                    .get(slot.as_usize() % T::SlotsPerEpoch::to_usize())
                    .map(|&index| Proposer {
                        index,
                        fork: cache.fork,
                    })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn insert(
        &mut self,
        key: (Epoch, Hash256),
        proposers: Vec<usize>,
        fork: Fork,
    ) -> Result<(), BeaconStateError> {
        if !self.cache.contains(&key) {
            self.cache.put(
                key,
                EpochBlockProposers {
                    epoch: key.0,
                    fork,
                    proposers: proposers.into(),
                    _phantom: <_>::default(),
                },
            );
        }

        Ok(())
    }
}
