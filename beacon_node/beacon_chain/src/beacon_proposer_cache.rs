//! The `BeaconProposer` cache stores the proposer indices for some epoch.
//!
//! This cache is keyed by `(epoch, block_root)` where `block_root` is the block root at
//! `end_slot(epoch - 1)`. We make the assertion that the proposer shuffling is identical for all
//! blocks in `epoch` which share the common ancestor of `block_root`.
//!
//! The cache is a fairly unintelligent LRU cache that is not pruned after finality. This makes it
//! very simple to reason about, but it might store values that are useless due to finalization. The
//! values it stores are very small, so this should not be an issue.

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use fork_choice::ExecutionStatus;
use lru::LruCache;
use smallvec::SmallVec;
use state_processing::state_advance::partial_state_advance;
use std::cmp::Ordering;
use types::{
    BeaconState, BeaconStateError, ChainSpec, CloneConfig, Epoch, EthSpec, Fork, Hash256, Slot,
    Unsigned,
};

/// The number of sets of proposer indices that should be cached.
const CACHE_SIZE: usize = 16;

/// This value is fairly unimportant, it's used to avoid heap allocations. The result of it being
/// incorrect is non-substantial from a consensus perspective (and probably also from a
/// performance perspective).
pub const TYPICAL_SLOTS_PER_EPOCH: usize = 32;

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

/// Compute the proposer duties using the head state without cache.
pub fn compute_proposer_duties_from_head<T: BeaconChainTypes>(
    request_epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<(Vec<usize>, Hash256, ExecutionStatus, Fork), BeaconChainError> {
    // Atomically collect information about the head whilst holding the canonical head `Arc` as
    // short as possible.
    let (mut state, head_state_root, head_block_root) = {
        let head = chain.canonical_head.cached_head();
        // Take a copy of the head state.
        let head_state = head
            .snapshot
            .beacon_state
            .clone_with(CloneConfig::committee_caches_only());
        let head_state_root = head.head_state_root();
        let head_block_root = head.head_block_root();
        (head_state, head_state_root, head_block_root)
    };

    let execution_status = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block_execution_status(&head_block_root)
        .ok_or(BeaconChainError::HeadMissingFromForkChoice(head_block_root))?;

    // Advance the state into the requested epoch.
    ensure_state_is_in_epoch(&mut state, head_state_root, request_epoch, &chain.spec)?;

    let indices = state
        .get_beacon_proposer_indices(&chain.spec)
        .map_err(BeaconChainError::from)?;

    let dependent_root = state
        // The only block which decides its own shuffling is the genesis block.
        .proposer_shuffling_decision_root(chain.genesis_block_root)
        .map_err(BeaconChainError::from)?;

    Ok((indices, dependent_root, execution_status, state.fork()))
}

/// If required, advance `state` to `target_epoch`.
///
/// ## Details
///
/// - Returns an error if `state.current_epoch() > target_epoch`.
/// - No-op if `state.current_epoch() == target_epoch`.
/// - It must be the case that `state.canonical_root() == state_root`, but this function will not
///     check that.
pub fn ensure_state_is_in_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Hash256,
    target_epoch: Epoch,
    spec: &ChainSpec,
) -> Result<(), BeaconChainError> {
    match state.current_epoch().cmp(&target_epoch) {
        // Protects against an inconsistent slot clock.
        Ordering::Greater => Err(BeaconStateError::SlotOutOfBounds.into()),
        // The state needs to be advanced.
        Ordering::Less => {
            let target_slot = target_epoch.start_slot(E::slots_per_epoch());
            partial_state_advance(state, Some(state_root), target_slot, spec)
                .map_err(BeaconChainError::from)
        }
        // The state is suitable, nothing to do.
        Ordering::Equal => Ok(()),
    }
}
