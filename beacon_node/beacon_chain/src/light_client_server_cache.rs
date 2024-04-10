use crate::errors::BeaconChainError;
use crate::{metrics, BeaconChainTypes, BeaconStore};
use parking_lot::{Mutex, RwLock};
use slog::{debug, Logger};
use ssz_types::FixedVector;
use std::num::NonZeroUsize;
use types::light_client_update::{FinalizedRootProofLen, FINALIZED_ROOT_INDEX};
use types::non_zero_usize::new_non_zero_usize;
use types::{
    BeaconBlockRef, BeaconState, ChainSpec, EthSpec, ForkName, Hash256, LightClientFinalityUpdate,
    LightClientOptimisticUpdate, Slot, SyncAggregate,
};

/// A prev block cache miss requires to re-generate the state of the post-parent block. Items in the
/// prev block cache are very small 32 * (6 + 1) = 224 bytes. 32 is an arbitrary number that
/// represents unlikely re-orgs, while keeping the cache very small.
const PREV_BLOCK_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(32);

/// This cache computes light client messages ahead of time, required to satisfy p2p and API
/// requests. These messages include proofs on historical states, so on-demand computation is
/// expensive.
///
pub struct LightClientServerCache<T: BeaconChainTypes> {
    /// Tracks a single global latest finality update out of all imported blocks.
    ///
    /// TODO: Active discussion with @etan-status if this cache should be fork aware to return
    /// latest canonical (update with highest signature slot, where its attested header is part of
    /// the head chain) instead of global latest (update with highest signature slot, out of all
    /// branches).
    latest_finality_update: RwLock<Option<LightClientFinalityUpdate<T::EthSpec>>>,
    /// Tracks a single global latest optimistic update out of all imported blocks.
    latest_optimistic_update: RwLock<Option<LightClientOptimisticUpdate<T::EthSpec>>>,
    /// Caches state proofs by block root
    prev_block_cache: Mutex<lru::LruCache<Hash256, LightClientCachedData>>,
}

impl<T: BeaconChainTypes> LightClientServerCache<T> {
    pub fn new() -> Self {
        Self {
            latest_finality_update: None.into(),
            latest_optimistic_update: None.into(),
            prev_block_cache: lru::LruCache::new(PREV_BLOCK_CACHE_SIZE).into(),
        }
    }

    /// Compute and cache state proofs for latter production of light-client messages. Does not
    /// trigger block replay.
    pub fn cache_state_data(
        &self,
        spec: &ChainSpec,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        block_post_state: &mut BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let _timer = metrics::start_timer(&metrics::LIGHT_CLIENT_SERVER_CACHE_STATE_DATA_TIMES);

        // Only post-altair
        if spec.fork_name_at_slot::<T::EthSpec>(block.slot()) == ForkName::Base {
            return Ok(());
        }

        // Persist in memory cache for a descendent block

        let cached_data = LightClientCachedData::from_state(block_post_state)?;
        self.prev_block_cache.lock().put(block_root, cached_data);

        Ok(())
    }

    /// Given a block with a SyncAggregte computes better or more recent light client updates. The
    /// results are cached either on disk or memory to be served via p2p and rest API
    pub fn recompute_and_cache_updates(
        &self,
        store: BeaconStore<T>,
        block_parent_root: &Hash256,
        block_slot: Slot,
        sync_aggregate: &SyncAggregate<T::EthSpec>,
        log: &Logger,
        chain_spec: &ChainSpec,
    ) -> Result<(), BeaconChainError> {
        let _timer =
            metrics::start_timer(&metrics::LIGHT_CLIENT_SERVER_CACHE_RECOMPUTE_UPDATES_TIMES);

        let signature_slot = block_slot;
        let attested_block_root = block_parent_root;

        let attested_block =
            store
                .get_full_block(attested_block_root)?
                .ok_or(BeaconChainError::DBInconsistent(format!(
                    "Block not available {:?}",
                    attested_block_root
                )))?;

        let cached_parts = self.get_or_compute_prev_block_cache(
            store.clone(),
            attested_block_root,
            &attested_block.state_root(),
            attested_block.slot(),
        )?;

        let attested_slot = attested_block.slot();

        // Spec: Full nodes SHOULD provide the LightClientOptimisticUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        let is_latest_optimistic = match &self.latest_optimistic_update.read().clone() {
            Some(latest_optimistic_update) => {
                is_latest_optimistic_update(latest_optimistic_update, attested_slot, signature_slot)
            }
            None => true,
        };
        if is_latest_optimistic {
            // can create an optimistic update, that is more recent
            *self.latest_optimistic_update.write() = Some(LightClientOptimisticUpdate::new(
                &attested_block,
                sync_aggregate.clone(),
                signature_slot,
                chain_spec,
            )?);
        };

        // Spec: Full nodes SHOULD provide the LightClientFinalityUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        let is_latest_finality = match &self.latest_finality_update.read().clone() {
            Some(latest_finality_update) => {
                is_latest_finality_update(latest_finality_update, attested_slot, signature_slot)
            }
            None => true,
        };
        if is_latest_finality & !cached_parts.finalized_block_root.is_zero() {
            // Immediately after checkpoint sync the finalized block may not be available yet.
            if let Some(finalized_block) =
                store.get_full_block(&cached_parts.finalized_block_root)?
            {
                *self.latest_finality_update.write() = Some(LightClientFinalityUpdate::new(
                    &attested_block,
                    &finalized_block,
                    cached_parts.finality_branch.clone(),
                    sync_aggregate.clone(),
                    signature_slot,
                    chain_spec,
                )?);
            } else {
                debug!(
                    log,
                    "Finalized block not available in store for light_client server";
                    "finalized_block_root" => format!("{}", cached_parts.finalized_block_root),
                );
            }
        }

        Ok(())
    }

    /// Retrieves prev block cached data from cache. If not present re-computes by retrieving the
    /// parent state, and inserts an entry to the cache.
    ///
    /// In separate function since FnOnce of get_or_insert can not be fallible.
    fn get_or_compute_prev_block_cache(
        &self,
        store: BeaconStore<T>,
        block_root: &Hash256,
        block_state_root: &Hash256,
        block_slot: Slot,
    ) -> Result<LightClientCachedData, BeaconChainError> {
        // Attempt to get the value from the cache first.
        if let Some(cached_parts) = self.prev_block_cache.lock().get(block_root) {
            return Ok(cached_parts.clone());
        }
        metrics::inc_counter(&metrics::LIGHT_CLIENT_SERVER_CACHE_PREV_BLOCK_CACHE_MISS);

        // Compute the value, handling potential errors.
        let mut state = store
            .get_state(block_state_root, Some(block_slot))?
            .ok_or_else(|| {
                BeaconChainError::DBInconsistent(format!("Missing state {:?}", block_state_root))
            })?;
        let new_value = LightClientCachedData::from_state(&mut state)?;

        // Insert value and return owned
        self.prev_block_cache
            .lock()
            .put(*block_root, new_value.clone());
        Ok(new_value)
    }

    pub fn get_latest_finality_update(&self) -> Option<LightClientFinalityUpdate<T::EthSpec>> {
        self.latest_finality_update.read().clone()
    }

    pub fn get_latest_optimistic_update(&self) -> Option<LightClientOptimisticUpdate<T::EthSpec>> {
        self.latest_optimistic_update.read().clone()
    }
}

impl<T: BeaconChainTypes> Default for LightClientServerCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

type FinalityBranch = FixedVector<Hash256, FinalizedRootProofLen>;

#[derive(Clone)]
struct LightClientCachedData {
    finality_branch: FinalityBranch,
    finalized_block_root: Hash256,
}

impl LightClientCachedData {
    fn from_state<E: EthSpec>(state: &mut BeaconState<E>) -> Result<Self, BeaconChainError> {
        Ok(Self {
            finality_branch: state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?.into(),
            finalized_block_root: state.finalized_checkpoint().root,
        })
    }
}

// Implements spec prioritization rules:
// > Full nodes SHOULD provide the LightClientFinalityUpdate with the highest attested_header.beacon.slot (if multiple, highest signature_slot)
//
// ref: https://github.com/ethereum/consensus-specs/blob/113c58f9bf9c08867f6f5f633c4d98e0364d612a/specs/altair/light-client/full-node.md#create_light_client_finality_update
fn is_latest_finality_update<E: EthSpec>(
    prev: &LightClientFinalityUpdate<E>,
    attested_slot: Slot,
    signature_slot: Slot,
) -> bool {
    let prev_slot = prev.get_attested_header_slot();
    if attested_slot > prev_slot {
        true
    } else {
        attested_slot == prev_slot && signature_slot > *prev.signature_slot()
    }
}

// Implements spec prioritization rules:
// > Full nodes SHOULD provide the LightClientOptimisticUpdate with the highest attested_header.beacon.slot (if multiple, highest signature_slot)
//
// ref: https://github.com/ethereum/consensus-specs/blob/113c58f9bf9c08867f6f5f633c4d98e0364d612a/specs/altair/light-client/full-node.md#create_light_client_optimistic_update
fn is_latest_optimistic_update<E: EthSpec>(
    prev: &LightClientOptimisticUpdate<E>,
    attested_slot: Slot,
    signature_slot: Slot,
) -> bool {
    let prev_slot = prev.get_slot();
    if attested_slot > prev_slot {
        true
    } else {
        attested_slot == prev_slot && signature_slot > *prev.signature_slot()
    }
}
