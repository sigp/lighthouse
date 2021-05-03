//! The `BeaconProposer` cache stores the proposer indices for some epoch.
//!
//! This cache is keyed by `(epoch, block_root)` where `block_root` is the block root at
//! `end_slot(epoch - 1)`. We make the assertion that the proposer shuffling is identical for all
//! blocks in `epoch` which share the common ancestor of `block_root`.
//!
//! The cache is a fairly unintelligent LRU cache that is not pruned after finality. This makes it
//! very simple to reason about, but it might store values that are useless due to finalization. The
//! values it stores are very small, so this should not be an issue.

use lru::LruCache;
use smallvec::SmallVec;
use types::{BeaconStateError, Epoch, EthSpec, Fork, Hash256, Slot, Unsigned};

/// The number of sets of proposer indices that should be cached.
const CACHE_SIZE: usize = 16;

/// This value is fairly unimportant, it's used to avoid heap allocations. The result of it being
/// incorrect is non-substantial from a consensus perspective (and probably also from a
/// performance perspective).
const TYPICAL_SLOTS_PER_EPOCH: usize = 32;

/// For some given slot, this contains the proposer index (`index`) and the `fork` that should be
/// used to verify their signature.
pub struct Proposer {
    pub index: usize,
    pub fork: Fork,
}

/// The list of proposers for some given `epoch`, alongside the `fork` that should be used to verify
/// their signatures.
pub struct EpochBlockProposers {
    /// The epoch to which the proposers pertain.
    epoch: Epoch,
    /// The fork that should be used to verify proposer signatures.
    fork: Fork,
    /// A list of length `T::EthSpec::slots_per_epoch()`, representing the proposers for each slot
    /// in that epoch.
    ///
    /// E.g., if `self.epoch == 1`, then `self.proposers[0]` contains the proposer for slot `32`.
    proposers: SmallVec<[usize; TYPICAL_SLOTS_PER_EPOCH]>,
}

/// A cache to store the proposers for some epoch.
///
/// See the module-level documentation for more information.
pub struct BeaconProposerCache {
    cache: LruCache<(Epoch, Hash256), EpochBlockProposers>,
}

impl Default for BeaconProposerCache {
    fn default() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }
}

impl BeaconProposerCache {
    /// If it is cached, returns the proposer for the block at `slot` where the block has the
    /// ancestor block root of `shuffling_decision_block` at `end_slot(slot.epoch() - 1)`.
    pub fn get_slot<T: EthSpec>(
        &mut self,
        shuffling_decision_block: Hash256,
        slot: Slot,
    ) -> Option<Proposer> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let key = (epoch, shuffling_decision_block);
        if let Some(cache) = self.cache.get(&key) {
            // This `if` statement is likely unnecessary, but it feels like good practice.
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

    /// As per `Self::get_slot`, but returns all proposers in all slots for the given `epoch`.
    ///
    /// The nth slot in the returned `SmallVec` will be equal to the nth slot in the given `epoch`.
    /// E.g., if `epoch == 1` then `smallvec[0]` refers to slot 32 (assuming `SLOTS_PER_EPOCH ==
    /// 32`).
    pub fn get_epoch<T: EthSpec>(
        &mut self,
        shuffling_decision_block: Hash256,
        epoch: Epoch,
    ) -> Option<&SmallVec<[usize; TYPICAL_SLOTS_PER_EPOCH]>> {
        let key = (epoch, shuffling_decision_block);
        self.cache.get(&key).map(|cache| &cache.proposers)
    }

    /// Insert the proposers into the cache.
    ///
    /// See `Self::get` for a description of `shuffling_decision_block`.
    ///
    /// The `fork` value must be valid to verify proposer signatures in `epoch`.
    pub fn insert(
        &mut self,
        epoch: Epoch,
        shuffling_decision_block: Hash256,
        proposers: Vec<usize>,
        fork: Fork,
    ) -> Result<(), BeaconStateError> {
        let key = (epoch, shuffling_decision_block);
        if !self.cache.contains(&key) {
            self.cache.put(
                key,
                EpochBlockProposers {
                    epoch,
                    fork,
                    proposers: proposers.into(),
                },
            );
        }

        Ok(())
    }
}
