use crate::errors::BeaconChainError;
use crate::{metrics, BeaconChainTypes, BeaconStore};
use parking_lot::{Mutex, RwLock};
use safe_arith::SafeArith;
use slog::{debug, Logger};
use ssz::Decode;
use std::num::NonZeroUsize;
use std::sync::Arc;
use store::DBColumn;
use store::KeyValueStore;
use tree_hash::TreeHash;
use types::non_zero_usize::new_non_zero_usize;
use types::{
    BeaconBlockRef, BeaconState, ChainSpec, Checkpoint, EthSpec, ForkName, Hash256,
    LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
    LightClientUpdate, MerkleProof, Slot, SyncAggregate, SyncCommittee,
};

/// A prev block cache miss requires to re-generate the state of the post-parent block. Items in the
/// prev block cache are very small 32 * (6 + 1) = 224 bytes. 32 is an arbitrary number that
/// represents unlikely re-orgs, while keeping the cache very small.
const PREV_BLOCK_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(32);

/// This cache computes light client messages ahead of time, required to satisfy p2p and API
/// requests. These messages include proofs on historical states, so on-demand computation is
/// expensive.
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
    /// Caches the most recent light client update
    latest_light_client_update: RwLock<Option<LightClientUpdate<T::EthSpec>>>,
    /// Caches the current sync committee,
    latest_written_current_sync_committee: RwLock<Option<Arc<SyncCommittee<T::EthSpec>>>>,
    /// Caches state proofs by block root
    prev_block_cache: Mutex<lru::LruCache<Hash256, LightClientCachedData<T::EthSpec>>>,
}

impl<T: BeaconChainTypes> LightClientServerCache<T> {
    pub fn new() -> Self {
        Self {
            latest_finality_update: None.into(),
            latest_optimistic_update: None.into(),
            latest_light_client_update: None.into(),
            latest_written_current_sync_committee: None.into(),
            prev_block_cache: lru::LruCache::new(PREV_BLOCK_CACHE_SIZE).into(),
        }
    }

    /// Compute and cache state proofs for latter production of light-client messages. Does not
    /// trigger block replay.
    pub(crate) fn cache_state_data(
        &self,
        spec: &ChainSpec,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        block_post_state: &mut BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let _timer = metrics::start_timer(&metrics::LIGHT_CLIENT_SERVER_CACHE_STATE_DATA_TIMES);
        let fork_name = spec.fork_name_at_slot::<T::EthSpec>(block.slot());
        // Only post-altair
        if fork_name.altair_enabled() {
            // Persist in memory cache for a descendent block
            let cached_data = LightClientCachedData::from_state(block_post_state)?;
            self.prev_block_cache.lock().put(block_root, cached_data);
        }

        Ok(())
    }

    /// Given a block with a SyncAggregate computes better or more recent light client updates. The
    /// results are cached either on disk or memory to be served via p2p and rest API
    pub fn recompute_and_cache_updates(
        &self,
        store: BeaconStore<T>,
        block_slot: Slot,
        block_parent_root: &Hash256,
        sync_aggregate: &SyncAggregate<T::EthSpec>,
        log: &Logger,
        chain_spec: &ChainSpec,
    ) -> Result<(), BeaconChainError> {
        metrics::inc_counter(&metrics::LIGHT_CLIENT_SERVER_CACHE_PROCESSING_REQUESTS);
        let _timer =
            metrics::start_timer(&metrics::LIGHT_CLIENT_SERVER_CACHE_RECOMPUTE_UPDATES_TIMES);

        let signature_slot = block_slot;
        let attested_block_root = block_parent_root;

        let sync_period = block_slot
            .epoch(T::EthSpec::slots_per_epoch())
            .sync_committee_period(chain_spec)?;

        let attested_block = store.get_blinded_block(attested_block_root)?.ok_or(
            BeaconChainError::DBInconsistent(format!(
                "Block not available {:?}",
                attested_block_root
            )),
        )?;

        let cached_parts = self.get_or_compute_prev_block_cache(
            store.clone(),
            attested_block_root,
            &attested_block.state_root(),
            attested_block.slot(),
        )?;

        let finalized_period = cached_parts
            .finalized_checkpoint
            .epoch
            .sync_committee_period(chain_spec)?;

        store.store_sync_committee_branch(
            attested_block.message().tree_hash_root(),
            &cached_parts.current_sync_committee_branch,
        )?;

        self.store_current_sync_committee(&store, &cached_parts, sync_period, finalized_period)?;

        let attested_slot = attested_block.slot();

        let maybe_finalized_block = store.get_blinded_block(&cached_parts.finalized_block_root)?;

        let sync_period = block_slot
            .epoch(T::EthSpec::slots_per_epoch())
            .sync_committee_period(chain_spec)?;

        // Spec: Full nodes SHOULD provide the LightClientOptimisticUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        let is_latest_optimistic = match &self.latest_optimistic_update.read().clone() {
            Some(latest_optimistic_update) => {
                latest_optimistic_update.is_latest(attested_slot, signature_slot)
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
                latest_finality_update.is_latest(attested_slot, signature_slot)
            }
            None => true,
        };

        if is_latest_finality & !cached_parts.finalized_block_root.is_zero() {
            // Immediately after checkpoint sync the finalized block may not be available yet.
            if let Some(finalized_block) = maybe_finalized_block.as_ref() {
                *self.latest_finality_update.write() = Some(LightClientFinalityUpdate::new(
                    &attested_block,
                    finalized_block,
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

        let new_light_client_update = LightClientUpdate::new(
            sync_aggregate,
            block_slot,
            cached_parts.next_sync_committee,
            cached_parts.next_sync_committee_branch,
            cached_parts.finality_branch,
            &attested_block,
            maybe_finalized_block.as_ref(),
            chain_spec,
        )?;

        // Spec: Full nodes SHOULD provide the best derivable LightClientUpdate (according to is_better_update)
        // for each sync committee period
        let prev_light_client_update =
            self.get_light_client_update(&store, sync_period, chain_spec)?;

        let should_persist_light_client_update =
            if let Some(prev_light_client_update) = prev_light_client_update {
                prev_light_client_update
                    .is_better_light_client_update(&new_light_client_update, chain_spec)?
            } else {
                true
            };

        if should_persist_light_client_update {
            store.store_light_client_update(sync_period, &new_light_client_update)?;
            *self.latest_light_client_update.write() = Some(new_light_client_update);
        }

        metrics::inc_counter(&metrics::LIGHT_CLIENT_SERVER_CACHE_PROCESSING_SUCCESSES);
        Ok(())
    }

    fn store_current_sync_committee(
        &self,
        store: &BeaconStore<T>,
        cached_parts: &LightClientCachedData<T::EthSpec>,
        sync_committee_period: u64,
        finalized_period: u64,
    ) -> Result<(), BeaconChainError> {
        if let Some(latest_sync_committee) =
            self.latest_written_current_sync_committee.read().clone()
        {
            if latest_sync_committee == cached_parts.current_sync_committee {
                return Ok(());
            }
        };

        if finalized_period + 1 >= sync_committee_period {
            store.store_sync_committee(
                sync_committee_period,
                &cached_parts.current_sync_committee,
            )?;
            *self.latest_written_current_sync_committee.write() =
                Some(cached_parts.current_sync_committee.clone());
        }

        Ok(())
    }

    /// Used to fetch the most recently persisted light client update for the given `sync_committee_period`.
    /// It first checks the `latest_light_client_update` cache before querying the db.
    ///
    /// Note: Should not be used outside the light client server, as it also caches the fetched
    /// light client update.
    fn get_light_client_update(
        &self,
        store: &BeaconStore<T>,
        sync_committee_period: u64,
        chain_spec: &ChainSpec,
    ) -> Result<Option<LightClientUpdate<T::EthSpec>>, BeaconChainError> {
        if let Some(latest_light_client_update) = self.latest_light_client_update.read().clone() {
            let latest_lc_update_sync_committee_period = latest_light_client_update
                .signature_slot()
                .epoch(T::EthSpec::slots_per_epoch())
                .sync_committee_period(chain_spec)?;
            if latest_lc_update_sync_committee_period == sync_committee_period {
                return Ok(Some(latest_light_client_update));
            }
        }

        if let Some(light_client_update) = store.get_light_client_update(sync_committee_period)? {
            *self.latest_light_client_update.write() = Some(light_client_update.clone());
            return Ok(Some(light_client_update));
        }

        Ok(None)
    }

    pub fn get_light_client_updates(
        &self,
        store: &BeaconStore<T>,
        start_period: u64,
        count: u64,
        chain_spec: &ChainSpec,
    ) -> Result<Vec<LightClientUpdate<T::EthSpec>>, BeaconChainError> {
        let column = DBColumn::LightClientUpdate;
        let mut light_client_updates = vec![];
        for res in store
            .hot_db
            .iter_column_from::<Vec<u8>>(column, &start_period.to_le_bytes())
        {
            let (sync_committee_bytes, light_client_update_bytes) = res?;
            let sync_committee_period = u64::from_ssz_bytes(&sync_committee_bytes)
                .map_err(store::errors::Error::SszDecodeError)?;

            if sync_committee_period >= start_period + count {
                break;
            }

            let epoch = sync_committee_period
                .safe_mul(chain_spec.epochs_per_sync_committee_period.into())?;

            let fork_name = chain_spec.fork_name_at_epoch(epoch.into());

            let light_client_update =
                LightClientUpdate::from_ssz_bytes(&light_client_update_bytes, &fork_name)
                    .map_err(store::errors::Error::SszDecodeError)?;

            light_client_updates.push(light_client_update);
        }
        Ok(light_client_updates)
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
    ) -> Result<LightClientCachedData<T::EthSpec>, BeaconChainError> {
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

    /// Fetches a light client bootstrap for a given finalized checkpoint `block_root`. We eagerly persist
    /// `sync_committee_branch and `sync_committee` to allow for a more efficient bootstrap construction.
    ///
    /// Note: It should be the case that a `sync_committee_branch` and `sync_committee` exist in the db
    /// for a finalized checkpoint block root. However, we currently have no backfill mechanism for these values.
    /// Therefore, `sync_committee_branch` and `sync_committee` are only persisted while a node is synced.
    #[allow(clippy::type_complexity)]
    pub fn get_light_client_bootstrap(
        &self,
        store: &BeaconStore<T>,
        block_root: &Hash256,
        finalized_period: u64,
        chain_spec: &ChainSpec,
    ) -> Result<Option<(LightClientBootstrap<T::EthSpec>, ForkName)>, BeaconChainError> {
        let Some(block) = store.get_blinded_block(block_root)? else {
            return Err(BeaconChainError::LightClientBootstrapError(format!(
                "Block root {block_root} not found"
            )));
        };

        let (_, slot) = (block.state_root(), block.slot());

        let fork_name = chain_spec.fork_name_at_slot::<T::EthSpec>(slot);

        let sync_committee_period = block
            .slot()
            .epoch(T::EthSpec::slots_per_epoch())
            .sync_committee_period(chain_spec)?;

        let Some(current_sync_committee_branch) = store.get_sync_committee_branch(block_root)?
        else {
            return Err(BeaconChainError::LightClientBootstrapError(format!(
                "Sync committee branch for block root {:?} not found",
                block_root
            )));
        };

        if sync_committee_period > finalized_period {
            return Err(BeaconChainError::LightClientBootstrapError(
                format!("The blocks sync committee period {sync_committee_period} is greater than the current finalized period {finalized_period}"),
            ));
        }

        let Some(current_sync_committee) = store.get_sync_committee(sync_committee_period)? else {
            return Err(BeaconChainError::LightClientBootstrapError(format!(
                "Sync committee for period {sync_committee_period} not found"
            )));
        };

        let light_client_bootstrap = LightClientBootstrap::new(
            &block,
            Arc::new(current_sync_committee),
            current_sync_committee_branch,
            chain_spec,
        )?;

        Ok(Some((light_client_bootstrap, fork_name)))
    }
}

impl<T: BeaconChainTypes> Default for LightClientServerCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct LightClientCachedData<E: EthSpec> {
    finalized_checkpoint: Checkpoint,
    finality_branch: MerkleProof,
    next_sync_committee_branch: MerkleProof,
    current_sync_committee_branch: MerkleProof,
    next_sync_committee: Arc<SyncCommittee<E>>,
    current_sync_committee: Arc<SyncCommittee<E>>,
    finalized_block_root: Hash256,
}

impl<E: EthSpec> LightClientCachedData<E> {
    fn from_state(state: &mut BeaconState<E>) -> Result<Self, BeaconChainError> {
        let (finality_branch, next_sync_committee_branch, current_sync_committee_branch) = (
            state.compute_finalized_root_proof()?,
            state.compute_current_sync_committee_proof()?,
            state.compute_next_sync_committee_proof()?,
        );
        Ok(Self {
            finalized_checkpoint: state.finalized_checkpoint(),
            finality_branch,
            next_sync_committee: state.next_sync_committee()?.clone(),
            current_sync_committee: state.current_sync_committee()?.clone(),
            next_sync_committee_branch,
            current_sync_committee_branch,
            finalized_block_root: state.finalized_checkpoint().root,
        })
    }
}
