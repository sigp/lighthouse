use crate::errors::BeaconChainError;
use crate::{metrics, BeaconChainTypes, BeaconStore};
use parking_lot::{Mutex, RwLock};
use safe_arith::{ArithError, SafeArith};
use slog::{debug, Logger};
use ssz::Decode;
use ssz::Encode;
use ssz_types::FixedVector;
use std::num::NonZeroUsize;
use std::sync::Arc;
use store::DBColumn;
use store::KeyValueStore;
use types::light_client_update::{
    FinalizedRootProofLen, NextSyncCommitteeProofLen, FINALIZED_ROOT_INDEX,
    NEXT_SYNC_COMMITTEE_INDEX,
};
use types::non_zero_usize::new_non_zero_usize;
use types::{
    BeaconBlockRef, BeaconState, ChainSpec, Epoch, EthSpec, ForkName, Hash256,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate, Slot, SyncAggregate,
    SyncCommittee,
};

/// A prev block cache miss requires to re-generate the state of the post-parent block. Items in the
/// prev block cache are very small 32 * (6 + 1) = 224 bytes. 32 is an arbitrary number that
/// represents unlikely re-orgs, while keeping the cache very small.
// TODO(lightclientupdate) this cache size has now increased
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
    prev_block_cache: Mutex<lru::LruCache<Hash256, LightClientCachedData<T::EthSpec>>>,
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

                let new_light_client_update = LightClientUpdate::new(
                    sync_aggregate,
                    block_slot,
                    cached_parts.next_sync_committee,
                    cached_parts.next_sync_committee_branch,
                    cached_parts.finality_branch,
                    &attested_block,
                    &finalized_block,
                    chain_spec,
                )?;

                let sync_period = block_slot
                    .epoch(T::EthSpec::slots_per_epoch())
                    .sync_committee_period(chain_spec)?;

                let prev_light_client_update =
                    self.get_light_client_update(&store, sync_period, chain_spec)?;

                if let Some(prev_light_client_update) = prev_light_client_update {
                    if is_better_light_client_update(
                        &prev_light_client_update,
                        &new_light_client_update,
                        chain_spec,
                    )? {
                        self.store_light_client_update(
                            &store,
                            sync_period,
                            &new_light_client_update,
                        )?;
                    }
                } else {
                    self.store_light_client_update(&store, sync_period, &new_light_client_update)?;
                }
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

    pub fn store_light_client_update(
        &self,
        store: &BeaconStore<T>,
        sync_committee_period: u64,
        light_client_update: &LightClientUpdate<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let column = DBColumn::LightClientUpdate;

        store.hot_db.put_bytes(
            column.into(),
            &sync_committee_period.to_le_bytes(),
            &light_client_update.as_ssz_bytes(),
        )?;

        Ok(())
    }

    pub fn get_light_client_update(
        &self,
        store: &BeaconStore<T>,
        sync_committee_period: u64,
        chain_spec: &ChainSpec,
    ) -> Result<Option<LightClientUpdate<T::EthSpec>>, BeaconChainError> {
        let column = DBColumn::LightClientUpdate;
        let res = store
            .hot_db
            .get_bytes(column.into(), &sync_committee_period.to_le_bytes())?;

        if let Some(light_client_update_bytes) = res {
            let epoch = sync_committee_period
                .safe_mul(chain_spec.epochs_per_sync_committee_period.into())?;

            let fork_name = chain_spec.fork_name_at_epoch(epoch.into());

            let light_client_update =
                LightClientUpdate::from_ssz_bytes(&light_client_update_bytes, fork_name)
                    .map_err(store::errors::Error::SszDecodeError)?;

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
            let epoch = sync_committee_period
                .safe_mul(chain_spec.epochs_per_sync_committee_period.into())?;

            let fork_name = chain_spec.fork_name_at_epoch(epoch.into());

            let light_client_update =
                LightClientUpdate::from_ssz_bytes(&light_client_update_bytes, fork_name)
                    .map_err(store::errors::Error::SszDecodeError)?;

            light_client_updates.push(light_client_update);

            if sync_committee_period >= start_period + count {
                break;
            }
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
}

impl<T: BeaconChainTypes> Default for LightClientServerCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

type FinalityBranch = FixedVector<Hash256, FinalizedRootProofLen>;
type NextSyncCommitteeBranch = FixedVector<Hash256, NextSyncCommitteeProofLen>;

#[derive(Clone)]
struct LightClientCachedData<E: EthSpec> {
    finality_branch: FinalityBranch,
    next_sync_committee_branch: NextSyncCommitteeBranch,
    next_sync_committee: Arc<SyncCommittee<E>>,
    finalized_block_root: Hash256,
}

impl<E: EthSpec> LightClientCachedData<E> {
    fn from_state(state: &mut BeaconState<E>) -> Result<Self, BeaconChainError> {
        Ok(Self {
            finality_branch: state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?.into(),
            next_sync_committee: state.next_sync_committee()?.clone(),
            next_sync_committee_branch: state
                .compute_merkle_proof(NEXT_SYNC_COMMITTEE_INDEX)?
                .into(),
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

// Implements spec prioritization rules:
// Full nodes SHOULD provide the best derivable LightClientUpdate for each sync committee period
// ref: https://github.com/ethereum/consensus-specs/blob/113c58f9bf9c08867f6f5f633c4d98e0364d612a/specs/altair/light-client/full-node.md#create_light_client_update
fn is_better_light_client_update<E: EthSpec>(
    prev: &LightClientUpdate<E>,
    new: &LightClientUpdate<E>,
    chain_spec: &ChainSpec,
) -> Result<bool, BeaconChainError> {
    // Compare super majority (> 2/3) sync committee participation
    let max_active_participants = new.sync_aggregate().sync_committee_bits.len();
    let new_active_participants = new.sync_aggregate().sync_committee_bits.num_set_bits();
    let prev_active_participants = prev.sync_aggregate().sync_committee_bits.num_set_bits();

    let new_has_super_majority =
        new_active_participants.safe_mul(3)? >= max_active_participants.safe_mul(2)?;
    let prev_has_super_majority =
        prev_active_participants.safe_mul(3)? >= max_active_participants.safe_mul(2)?;

    if new_has_super_majority != prev_has_super_majority {
        return Ok(new_has_super_majority & !prev_has_super_majority);
    }

    if !new_has_super_majority && new_active_participants != prev_active_participants {
        return Ok(new_active_participants > prev_active_participants);
    }

    let new_attested_header_slot = match new {
        LightClientUpdate::Altair(update) => update.attested_header.beacon.slot,
        LightClientUpdate::Capella(update) => update.attested_header.beacon.slot,
        LightClientUpdate::Deneb(update) => update.attested_header.beacon.slot,
    };

    let new_finalized_header_slot = match new {
        LightClientUpdate::Altair(update) => update.finalized_header.beacon.slot,
        LightClientUpdate::Capella(update) => update.finalized_header.beacon.slot,
        LightClientUpdate::Deneb(update) => update.finalized_header.beacon.slot,
    };

    let prev_attested_header_slot = match prev {
        LightClientUpdate::Altair(update) => update.attested_header.beacon.slot,
        LightClientUpdate::Capella(update) => update.attested_header.beacon.slot,
        LightClientUpdate::Deneb(update) => update.attested_header.beacon.slot,
    };

    let prev_finalized_header_slot = match prev {
        LightClientUpdate::Altair(update) => update.finalized_header.beacon.slot,
        LightClientUpdate::Capella(update) => update.finalized_header.beacon.slot,
        LightClientUpdate::Deneb(update) => update.finalized_header.beacon.slot,
    };

    let new_attested_header_sync_committee_period =
        compute_sync_committee_period_at_slot::<E>(new_attested_header_slot, chain_spec)?;

    let new_signature_slot_sync_committee_period =
        compute_sync_committee_period_at_slot::<E>(*new.signature_slot(), chain_spec)?;

    let prev_attested_header_sync_committee_period =
        compute_sync_committee_period_at_slot::<E>(prev_attested_header_slot, chain_spec)?;

    let prev_signature_slot_sync_committee_period =
        compute_sync_committee_period_at_slot::<E>(*prev.signature_slot(), chain_spec)?;

    // Compare presence of relevant sync committee
    let new_has_relevant_sync_committee = new.next_sync_committee_branch().is_empty()
        && (new_attested_header_sync_committee_period == new_signature_slot_sync_committee_period);

    let prev_has_relevant_sync_committee = prev.next_sync_committee_branch().is_empty()
        && (prev_attested_header_sync_committee_period
            == prev_signature_slot_sync_committee_period);

    if new_has_relevant_sync_committee != prev_has_relevant_sync_committee {
        return Ok(new_has_relevant_sync_committee);
    }

    // Compare indication of any finality
    let new_has_finality = new.finality_branch().is_empty();
    let prev_has_finality = prev.finality_branch().is_empty();
    if new_has_finality != prev_has_finality {
        return Ok(new_has_finality);
    }

    // Compare sync committee finality
    if new_has_finality {
        let new_has_sync_committee_finality =
            compute_sync_committee_period_at_slot::<E>(new_finalized_header_slot, chain_spec)?
                == compute_sync_committee_period_at_slot::<E>(
                    new_attested_header_slot,
                    chain_spec,
                )?;

        let prev_has_sync_committee_finality =
            compute_sync_committee_period_at_slot::<E>(prev_finalized_header_slot, chain_spec)?
                == compute_sync_committee_period_at_slot::<E>(
                    prev_attested_header_slot,
                    chain_spec,
                )?;

        if new_has_sync_committee_finality != prev_has_sync_committee_finality {
            return Ok(new_has_sync_committee_finality);
        }
    }

    // Tiebreaker 1: Sync committee participation beyond super majority
    if new_active_participants != prev_active_participants {
        return Ok(new_active_participants > prev_active_participants);
    }

    // Tiebreaker 2: Prefer older data (fewer changes to best)
    if new_attested_header_slot != prev_attested_header_slot {
        return Ok(new_attested_header_slot < prev_attested_header_slot);
    }

    return Ok(new.signature_slot() < prev.signature_slot());
}

fn compute_sync_committee_period_at_slot<E: EthSpec>(
    slot: Slot,
    chain_spec: &ChainSpec,
) -> Result<Epoch, ArithError> {
    slot.epoch(E::slots_per_epoch())
        .safe_div(chain_spec.epochs_per_sync_committee_period)
}
