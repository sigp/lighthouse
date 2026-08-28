//! This module builds out the data availability cache for Gloas. When a beacon block is received
//! over gossip/p2p we insert its bid into this cache, keyed by block root. As soon as the bid
//! is received we can begin using it to verify data columns.
//!
//! When a payload envelope is received and executed against the EL, it is inserted into this cache.
//! Once all required custody columns have been kzg verified and the envelope has been executed we can
//! import the envelope into fork choice and store it to disk.
//!
//! Note that the block must have arrived before the envelope or data columns can reach this cache.
//! Data columns require the bid (from the block) for verification. Columns that arrive before
//! the block are rejected with `BlockRootUnknown`.

use crate::data_availability_checker::{AvailabilityCheckError, MissingCellsError};
use crate::payload_envelope_verification::{
    AvailabilityPendingExecutedEnvelope, AvailableExecutedEnvelope,
};
use crate::{BeaconChainTypes, CustodyContext, metrics};
use hashlink::lru_cache::LruCache;
use kzg::Kzg;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{Span, debug, error, instrument};
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    PartialDataColumn, PartialDataColumnView,
};

mod pending_column;
mod pending_components;

use crate::data_column_verification::{
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn,
    KzgVerifiedCustodyPartialDataColumnGloas, KzgVerifiedDataColumn,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
use crate::partial_data_column_assembler::PartialMergeResult;
use pending_components::{PendingComponents, ReconstructColumnsDecision};
use types::{SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope};

/// The LRU Cache stores `PendingComponents`, which store the block root, the execution payload bid, and its associated column data.
/// The execution payload bid stores the kzg commitments which we use to verify against incoming column data.
/// Setting this to 32 keeps memory usage reasonable.
///
/// `PendingComponents` are now never removed from the cache manually and are only removed via LRU
/// eviction to prevent race conditions (#7961), so we expect this cache to be full all the time.
const AVAILABILITY_CACHE_CAPACITY: usize = 32;

/// What `update_pending_components` returns: the value that the update closure computed, next to
/// a read guard on the entry it updated.
type UpdatedComponents<'a, E, R> = (R, MappedRwLockReadGuard<'a, PendingComponents<E>>);

/// This type is returned after adding a bid / column to the `DataAvailabilityChecker`.
///
/// Indicates if the payloads data is fully `Available` or if we need more columns.
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedEnvelope<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(envelope) => {
                write!(f, "Available({:?})", envelope.block_root)
            }
        }
    }
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);
pub type AvailabilityAndPartialMergeResult<E> = (Availability<E>, PartialMergeResult<E>);

#[derive(Debug)]
pub enum DataColumnReconstructionResult<E: EthSpec> {
    Success(AvailabilityAndReconstructedColumns<E>),
    NotStarted(&'static str),
    RecoveredColumnsNotImported(&'static str),
}

/// Cache to hold data columns for payloads pending data availability.
///
/// In Gloas, beacon blocks can be immediately imported into fork choice. The execution payload
/// bid contains the payloads kzg commitments. This cache tracks data columns for payloads until all
/// required columns are received.
///
/// Usually data becomes available on its slot within a second of receiving its first component
/// over gossip. However, data may never become available if a malicious proposer does not
/// publish its data, or there are network issues. Components are only removed via LRU eviction.
pub struct PendingPayloadCache<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    availability_cache: RwLock<LruCache<Hash256, PendingComponents<T::EthSpec>>>,
    kzg: Arc<Kzg>,
    custody_context: Arc<CustodyContext<T>>,
    disable_get_blobs: bool,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> PendingPayloadCache<T> {
    pub fn new(
        kzg: Arc<Kzg>,
        custody_context: Arc<CustodyContext<T>>,
        disable_get_blobs: bool,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            availability_cache: RwLock::new(LruCache::new(AVAILABILITY_CACHE_CAPACITY)),
            kzg,
            custody_context,
            disable_get_blobs,
            spec,
        })
    }

    pub fn custody_context(&self) -> &Arc<CustodyContext<T>> {
        &self.custody_context
    }

    /// Returns all cached data columns for the given block root, if any.
    #[instrument(skip_all, level = "trace")]
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns())
        })
    }

    /// Returns the indices of cached data columns for the given block root.
    #[instrument(skip_all, level = "trace")]
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>> {
        self.peek_pending_components(block_root, |components| {
            components.map(|components| components.get_cached_data_columns_indices())
        })
    }

    /// Returns whether the custody requirement for `block_root` has been
    /// satisfied, independent of whether the payload envelope has been received
    /// or imported into fork choice.
    ///
    /// Returns `false` if the block is not present in the pending payload cache.
    #[instrument(skip_all, level = "trace")]
    pub fn is_blob_data_available(&self, block_root: &Hash256) -> bool {
        self.peek_pending_components(block_root, |components| {
            components.is_some_and(|c| {
                let num_expected_columns = c.num_columns_required(&self.custody_context);
                c.is_blob_data_available(num_expected_columns)
            })
        })
    }

    /// Return the cached Gloas payload bid for `block_root`, if present.
    pub fn get_bid(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<T::EthSpec>>> {
        self.peek_pending_components(block_root, |components| {
            components.map(|components| components.bid.clone())
        })
    }

    /// Return the executed payload envelope cached for `block_root` awaiting data availability,
    /// if present.
    pub fn get_executed_payload_envelope(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>> {
        self.peek_pending_components(block_root, |components| {
            components.and_then(|components| {
                components
                    .envelope
                    .as_ref()
                    .map(|envelope| envelope.envelope.clone())
            })
        })
    }

    /// Filter out cells that are already cached for the given column sidecar.
    /// Returns the cells that still need KZG verification, or `None` if all cells are cached.
    #[instrument(skip_all, level = "trace")]
    pub fn missing_cells_for_column_sidecar<'a>(
        &'_ self,
        data_column: &'a DataColumnSidecar<T::EthSpec>,
    ) -> Result<Option<PartialDataColumnView<'a, T::EthSpec>>, MissingCellsError> {
        let block_root = data_column.block_root();
        let column_index = *data_column.index();

        self.peek_pending_components(&block_root, |components| {
            let Some(cached) = components.and_then(|c| c.verified_data_columns.get(&column_index))
            else {
                return data_column.try_filter_to_partial_view(|_, _, _| Ok(true));
            };

            data_column.try_filter_to_partial_view(|cell_idx, cell, proof| {
                match cached.cell_matches(cell_idx, cell, proof) {
                    None => Ok(true),
                    Some(true) => Ok(false),
                    Some(false) => Err(MissingCellsError::MismatchesCachedColumn),
                }
            })
        })
    }

    /// Filter out cells that are already cached for the given partial column sidecar.
    /// Returns the cells that still need KZG verification, or `None` if all cells are cached.
    #[instrument(skip_all, level = "trace")]
    pub fn missing_cells_for_partial_column_sidecar<'a>(
        &'_ self,
        partial_data_column: &'a PartialDataColumn<T::EthSpec>,
    ) -> Result<Option<PartialDataColumnView<'a, T::EthSpec>>, MissingCellsError> {
        let block_root = *partial_data_column.block_root();
        let column_index = *partial_data_column.index();

        self.peek_pending_components(&block_root, |components| {
            let Some(cached) = components.and_then(|c| c.verified_data_columns.get(&column_index))
            else {
                return partial_data_column.sidecar().try_filter(|_, _, _| Ok(true));
            };

            partial_data_column
                .sidecar()
                .try_filter(|cell_idx, cell, proof| {
                    match cached.cell_matches(cell_idx, cell, proof) {
                        None => Ok(true),
                        Some(true) => Ok(false),
                        Some(false) => Err(MissingCellsError::MismatchesCachedColumn),
                    }
                })
        })
    }

    /// Insert an executed payload envelope into the cache and performs an availability check
    pub fn put_executed_payload_envelope(
        &self,
        executed_envelope: AvailabilityPendingExecutedEnvelope<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let beacon_block_root = executed_envelope.envelope.beacon_block_root();
        let bid = self
            .get_bid(&beacon_block_root)
            .ok_or(AvailabilityCheckError::MissingBid(beacon_block_root))?;

        let (_, pending_components) =
            self.update_pending_components(beacon_block_root, &bid, |pending_components| {
                pending_components.insert_executed_payload_envelope(executed_envelope);
            })?;

        pending_components.span.in_scope(|| {
            debug!(
                component = "executed envelope",
                status = pending_components.status_str(&self.custody_context),
                "Component added to data availability checker"
            );
        });

        self.check_availability(beacon_block_root, pending_components)
    }

    /// Inserts a bid into the pending payload cache.
    /// This will silently drop the bid if a bid for this block root already exists in the cache.
    pub fn insert_bid(&self, block_root: Hash256, bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>) {
        let mut write_lock = self.availability_cache.write();
        write_lock
            .entry(block_root)
            .or_insert_with(|| PendingComponents::new(block_root, bid));
    }

    /// Perform KZG verification on RPC custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available.
    #[instrument(skip_all, level = "trace")]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let bid = self
            .get_bid(&block_root)
            .ok_or(AvailabilityCheckError::MissingBid(block_root))?;
        let kzg_verified_columns = KzgVerifiedDataColumn::from_batch_with_scoring_and_commitments(
            custody_columns,
            &bid.message.blob_kzg_commitments,
            &self.kzg,
        )
        .map_err(AvailabilityCheckError::InvalidColumn)?;

        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self.custody_context.sampling_columns_for_epoch(epoch);
        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, &verified_custody_columns)
    }

    /// Perform KZG verification on gossip verified custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available
    #[instrument(skip_all, level = "trace")]
    pub fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let bid = self
            .get_bid(&block_root)
            .ok_or(AvailabilityCheckError::MissingBid(block_root))?;
        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self.custody_context.sampling_columns_for_epoch(epoch);
        let custody_columns = data_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, &custody_columns)
    }

    /// Merge KZG verified partial custody columns into the cache. Returns the columns that became
    /// fully populated as a result of this merge, plus the accumulated partials that gained cells
    /// (for republishing).
    #[instrument(skip_all, level = "trace")]
    pub fn merge_partial_data_columns(
        &self,
        block_root: Hash256,
        kzg_verified_partial_data_columns: &[KzgVerifiedCustodyPartialDataColumnGloas<
            T::EthSpec,
        >],
    ) -> Result<AvailabilityAndPartialMergeResult<T::EthSpec>, AvailabilityCheckError> {
        let bid = self
            .get_bid(&block_root)
            .ok_or(AvailabilityCheckError::MissingBid(block_root))?;

        let (outcome, pending_components) =
            self.update_pending_components(block_root, &bid, |pending_components| {
                pending_components.merge_partial_data_columns(kzg_verified_partial_data_columns)
            })?;

        let partial_merge_result =
            pending_components.to_partial_merge_result(outcome, self.disable_get_blobs);

        let availability = self.check_availability(block_root, pending_components)?;

        Ok((availability, partial_merge_result))
    }

    /// Returns the partial columns currently held for `block_root` so the caller can republish
    /// them after a local `getBlobs` fetch, and marks the entry as locally-fetched so subsequent
    /// merges don't trigger another republish wave.
    #[instrument(skip_all, level = "trace")]
    pub fn get_partials_and_mark_as_local_fetched(
        &self,
        block_root: Hash256,
        bid: &Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Vec<KzgVerifiedCustodyPartialDataColumnGloas<T::EthSpec>> {
        let Ok((_, pending_components)) =
            self.update_pending_components(block_root, bid, |components| {
                components.local_fetch_settled = true;
            })
        else {
            return Vec::new();
        };
        pending_components.get_cached_partial_data_columns()
    }

    /// Returns true if the given column is fully populated in the cache.
    pub fn is_column_complete(&self, block_root: &Hash256, column_index: ColumnIndex) -> bool {
        self.peek_pending_components(block_root, |components| {
            components.is_some_and(|c| {
                c.verified_data_columns
                    .get(&column_index)
                    .is_some_and(|column| column.is_complete())
            })
        })
    }

    /// Insert KZG verified columns into the cache.
    /// After insertion check if the envelope becomes available.
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        kzg_verified_data_columns: &[KzgVerifiedCustodyDataColumn<T::EthSpec>],
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let bid = self
            .get_bid(&block_root)
            .ok_or(AvailabilityCheckError::MissingBid(block_root))?;

        let (_, pending_components) =
            self.update_pending_components(block_root, &bid, |pending_components| {
                pending_components.merge_data_columns(kzg_verified_data_columns)
            })?;

        pending_components.span.in_scope(|| {
            debug!(
                component = "data_columns",
                status = pending_components.status_str(&self.custody_context),
                "Component added to data availability checker"
            );
        });

        self.check_availability(block_root, pending_components)
    }

    #[instrument(skip_all, level = "debug")]
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        let bid = self
            .get_bid(block_root)
            .ok_or(AvailabilityCheckError::MissingBid(*block_root))?;

        let verified_data_columns = match self.check_and_set_reconstruction_started(block_root) {
            ReconstructColumnsDecision::Yes(verified_data_columns) => verified_data_columns,
            ReconstructColumnsDecision::No(reason) => {
                return Ok(DataColumnReconstructionResult::NotStarted(reason));
            }
        };
        let existing_column_indices = verified_data_columns
            .iter()
            .map(|data_column| *data_column.index())
            .collect::<Vec<_>>();

        metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS);
        let timer = metrics::start_timer(&metrics::DATA_AVAILABILITY_RECONSTRUCTION_TIME);

        let all_data_columns = KzgVerifiedCustodyDataColumn::reconstruct_columns(
            &self.kzg,
            verified_data_columns,
            &bid.message.blob_kzg_commitments,
            &self.spec,
        )
        .map_err(|e| {
            error!(
                ?block_root,
                error = ?e,
                "Error reconstructing data columns"
            );
            self.handle_reconstruction_failure(block_root);
            metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES);
            AvailabilityCheckError::ReconstructColumnsError(e)
        })?;

        let slot = bid.message.slot;
        let columns_to_sample = self
            .custody_context()
            .sampling_columns_for_epoch(slot.epoch(T::EthSpec::slots_per_epoch()));

        let data_columns_to_import_and_publish = all_data_columns
            .into_iter()
            .filter(|d| {
                columns_to_sample.contains(&d.index())
                    && !existing_column_indices.contains(&d.index())
            })
            .collect::<Vec<_>>();

        metrics::stop_timer(timer);
        metrics::inc_counter_by(
            &metrics::DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS,
            data_columns_to_import_and_publish.len() as u64,
        );

        debug!(
            count = data_columns_to_import_and_publish.len(),
            ?block_root,
            %slot,
            "Reconstructed columns"
        );

        self.put_kzg_verified_custody_data_columns(*block_root, &data_columns_to_import_and_publish)
            .map(|availability| {
                DataColumnReconstructionResult::Success((
                    availability,
                    data_columns_to_import_and_publish
                        .into_iter()
                        .map(|d| d.clone_arc())
                        .collect::<Vec<_>>(),
                ))
            })
    }

    // ── Metrics ──

    /// Number of pending component entries in memory in the cache.
    pub fn cache_size(&self) -> usize {
        self.availability_cache.read().len()
    }

    // ── Internal helpers ──

    fn check_availability(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(available_envelope) =
            pending_components.make_available(&self.custody_context)?
        {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.availability_cache.write().get_mut(&block_root) {
                // Clean up span now that data is available
                components.span = Span::none();
            }

            // We never remove the pending components manually to avoid race conditions.
            // Components are only removed via LRU eviction as finality advances.
            Ok(Availability::Available(Box::new(available_envelope)))
        } else {
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Applies `update_fn` to the entry for `block_root` under the write lock, then downgrades to
    /// a read guard. Returns whatever `update_fn` computed, next to that guard.
    fn update_pending_components<R, F>(
        &self,
        block_root: Hash256,
        bid: &Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        update_fn: F,
    ) -> Result<UpdatedComponents<'_, T::EthSpec, R>, AvailabilityCheckError>
    where
        F: FnOnce(&mut PendingComponents<T::EthSpec>) -> R,
    {
        let mut write_lock = self.availability_cache.write();

        let outcome = {
            let pending_components = write_lock
                .entry(block_root)
                .or_insert_with(|| PendingComponents::new(block_root, bid.clone()));
            update_fn(pending_components)
        };

        let pending_components =
            RwLockReadGuard::try_map(RwLockWriteGuard::downgrade(write_lock), |cache| {
                cache.peek(&block_root)
            })
            .map_err(|_| {
                AvailabilityCheckError::Unexpected("pending components should exist".to_string())
            })?;

        Ok((outcome, pending_components))
    }

    fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.availability_cache.read().peek(block_root))
    }

    /// Check whether data column reconstruction should be attempted.
    /// TODO(gloas): rethink reconstruction for the cell model
    fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.availability_cache.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            return ReconstructColumnsDecision::No("block already imported");
        };

        let epoch = pending_components.bid.epoch();

        let total_column_count = T::EthSpec::number_of_columns();
        let sampling_column_count = self.custody_context.num_of_data_columns_to_sample(epoch);

        if pending_components.reconstruction_started {
            return ReconstructColumnsDecision::No("already started");
        }
        let received_column_count = pending_components.num_completed_columns();
        if received_column_count >= sampling_column_count {
            return ReconstructColumnsDecision::No("all sampling columns received");
        }
        if received_column_count < total_column_count / 2 {
            return ReconstructColumnsDecision::No("not enough columns");
        }

        pending_components.reconstruction_started = true;
        ReconstructColumnsDecision::Yes(pending_components.get_cached_data_columns())
    }

    /// This could mean some invalid data columns made it through to the `DataAvailabilityChecker`.
    /// In this case, we remove all data columns in `PendingComponents`, reset reconstruction
    /// status so that we can attempt to retrieve columns from peers again.
    fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        if let Some(pending_components_mut) = self.availability_cache.write().get_mut(block_root) {
            pending_components_mut.verified_data_columns = HashMap::new();
            pending_components_mut.reconstruction_started = false;
        }
    }

    /// Maintain the cache by removing entries older than the cutoff epoch.
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        let mut write_lock = self.availability_cache.write();
        let mut keys_to_remove = vec![];
        for (key, value) in write_lock.iter() {
            if value.bid.epoch() < cutoff_epoch {
                keys_to_remove.push(*key);
            }
        }
        for key in keys_to_remove {
            write_lock.remove(&key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod data_availability_checker_tests {
    use super::*;

    use crate::block_verification::PayloadVerificationOutcome;
    use crate::custody_context::NodeCustodyType;
    use crate::test_utils::{
        DiskHarnessType, NumBlobs, generate_data_column_indices_rand_order,
        generate_rand_block_and_data_columns, get_kzg,
    };
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgProof;
    use logging::create_test_tracing_subscriber;
    use slot_clock::{SlotClock, TestingSlotClock};
    use ssz_types::ProgressiveVariableList;
    use std::time::Duration;
    use types::{
        Cell, CellBitmap, ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequestsGloas,
        ForkName, MinimalEthSpec, PartialDataColumnGloas, PartialDataColumnSidecarGloas,
        SignedExecutionPayloadEnvelope, Slot, test_utils::test_unstructured,
    };

    type E = MinimalEthSpec;
    type T = DiskHarnessType<E>;

    const NUM_BLOBS: usize = 1;

    /// Stand up a cache + a 1-blob Gloas block for the given custody type. The bid is registered
    /// in the cache; `custody` is pre-filtered to the sampling subset.
    fn setup(node_custody: NodeCustodyType) -> Setup {
        setup_with(node_custody, NumBlobs::Number(NUM_BLOBS))
    }

    fn setup_zero_blob(node_custody: NodeCustodyType) -> Setup {
        setup_with(node_custody, NumBlobs::Number(0))
    }

    fn setup_with(node_custody: NodeCustodyType, num_blobs: NumBlobs) -> Setup {
        create_test_tracing_subscriber();
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let kzg = get_kzg(&spec);
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        let complete_blob_backfill = false;
        let custody_context = Arc::new(CustodyContext::<T>::new(
            node_custody,
            generate_data_column_indices_rand_order::<E>(),
            slot_clock,
            complete_blob_backfill,
            spec.clone(),
        ));
        let cache = Arc::new(
            PendingPayloadCache::<T>::new(kzg, custody_context, false, spec.clone())
                .expect("create cache"),
        );

        let mut u = test_unstructured();
        let (block, columns) =
            generate_rand_block_and_data_columns::<E>(ForkName::Gloas, num_blobs, &mut u, &spec)
                .expect("generate test block");
        let block_root = block.canonical_root();
        let bid = Arc::new(
            block
                .message()
                .body()
                .signed_execution_payload_bid()
                .expect("Gloas block has bid")
                .clone(),
        );
        cache.insert_bid(block_root, bid.clone());

        let epoch = bid.message.slot.epoch(E::slots_per_epoch());
        let sampling = cache.custody_context().sampling_columns_for_epoch(epoch);
        let custody = columns
            .into_iter()
            .filter(|c| sampling.contains(c.index()))
            .collect();

        Setup {
            cache,
            block_root,
            custody,
        }
    }

    struct Setup {
        cache: Arc<PendingPayloadCache<T>>,
        block_root: Hash256,
        custody: DataColumnSidecarList<E>,
    }

    impl Setup {
        fn put_envelope(&self) -> Availability<E> {
            self.cache
                .put_executed_payload_envelope(executed_envelope(self.block_root))
                .expect("put envelope")
        }

        fn put_columns(&self, columns: DataColumnSidecarList<E>) -> Availability<E> {
            self.cache
                .put_rpc_custody_columns(self.block_root, columns)
                .expect("put columns")
        }

        fn reconstruct(&self) -> Result<DataColumnReconstructionResult<E>, AvailabilityCheckError> {
            self.cache.reconstruct_data_columns(&self.block_root)
        }

        fn cached_indexes(&self) -> Vec<ColumnIndex> {
            self.cache
                .cached_data_column_indexes(&self.block_root)
                .expect("entry")
        }
    }

    /// Hand-rolled executed envelope with bypassed verification; the cache only inspects
    /// `beacon_block_root` and the verification outcome, never the signature or payload.
    fn executed_envelope(block_root: Hash256) -> AvailabilityPendingExecutedEnvelope<E> {
        AvailabilityPendingExecutedEnvelope {
            envelope: Arc::new(SignedExecutionPayloadEnvelope {
                message: ExecutionPayloadEnvelope {
                    payload: ExecutionPayloadGloas::default(),
                    execution_requests: ExecutionRequestsGloas::default(),
                    builder_index: 0,
                    beacon_block_root: block_root,
                    parent_beacon_block_root: Hash256::random(),
                },
                signature: bls::Signature::infinity().expect("infinity sig"),
            }),
            block_root,
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
            },
        }
    }

    #[track_caller]
    fn assert_missing(availability: Availability<E>) {
        assert!(
            matches!(availability, Availability::MissingComponents(_)),
            "expected MissingComponents, got {availability:?}",
        );
    }

    #[track_caller]
    fn assert_available(availability: Availability<E>) -> Box<AvailableExecutedEnvelope<E>> {
        match availability {
            Availability::Available(env) => env,
            other => panic!("expected Available, got {other:?}"),
        }
    }

    // ─── Tier 1: real-path availability flows ───────────────────────────────

    /// Envelope first → MissingComponents. Then all sampling columns → Available.
    #[tokio::test]
    async fn availability_arrives_envelope_first() {
        let s = setup(NodeCustodyType::Fullnode);
        assert_missing(s.put_envelope());
        let envelope = assert_available(s.put_columns(s.custody.clone()));
        assert_eq!(envelope.block_root, s.block_root);
        assert_eq!(envelope.envelope.columns.len(), s.custody.len());
    }

    /// Columns first → MissingComponents. Then envelope → Available.
    #[tokio::test]
    async fn availability_arrives_columns_first() {
        let s = setup(NodeCustodyType::Fullnode);
        assert_missing(s.put_columns(s.custody.clone()));
        let envelope = assert_available(s.put_envelope());
        assert_eq!(envelope.block_root, s.block_root);
        assert_eq!(envelope.envelope.columns.len(), s.custody.len());
    }

    /// N-1 columns + envelope is still MissingComponents; the Nth column flips to Available.
    /// Guards the strict count comparison in `make_available`.
    #[tokio::test]
    async fn partial_columns_then_complete() {
        let mut s = setup(NodeCustodyType::Fullnode);
        assert!(s.custody.len() >= 2, "needs at least 2 sampling columns");
        let last = s.custody.pop().expect("non-empty custody");

        s.put_envelope();
        assert_missing(s.put_columns(s.custody.clone()));
        assert_available(s.put_columns(vec![last]));
    }

    /// Zero-blob block + envelope → Available. Guards the `num_blobs_expected == 0` early-return
    /// in `make_available`.
    #[tokio::test]
    async fn zero_blob_envelope_immediately_available() {
        let s = setup_zero_blob(NodeCustodyType::Fullnode);
        let envelope = assert_available(s.put_envelope());
        assert!(envelope.envelope.columns.is_empty());
    }

    /// Receiving the same column twice keeps a single cache entry. Guards `PendingColumn::insert`
    /// staying only-if-empty under repeated arrivals.
    #[tokio::test]
    async fn dedups_repeated_column_inserts() {
        let s = setup(NodeCustodyType::Fullnode);
        let column = s.custody.first().cloned().expect("sampling column");
        let column_index = *column.index();
        s.put_columns(vec![column.clone()]);
        s.put_columns(vec![column]);

        assert_eq!(s.cached_indexes(), vec![column_index]);
        assert_eq!(
            s.cache.get_data_columns(s.block_root).map(|c| c.len()),
            Some(1),
        );
    }

    // ─── Tier 2: reconstruction state machine ───────────────────────────────
    //
    // Reconstruction only triggers when `total/2 ≤ received < sampling_count`. Fullnode's small
    // sampling count never satisfies this, so these tests use `Supernode`.

    /// Fewer than `number_of_columns / 2` columns received → reconstruction is `NotStarted`.
    #[tokio::test]
    async fn reconstruction_below_threshold_is_not_started() {
        let s = setup(NodeCustodyType::Supernode);
        let half = E::number_of_columns() / 2;
        s.put_columns(s.custody.iter().take(half - 1).cloned().collect());
        assert!(matches!(
            s.reconstruct().expect("reconstruct call"),
            DataColumnReconstructionResult::NotStarted("not enough columns")
        ));
    }

    /// All sampling columns received → reconstruction unnecessary, returns `NotStarted`.
    #[tokio::test]
    async fn reconstruction_already_complete_is_not_started() {
        let s = setup(NodeCustodyType::Supernode);
        s.put_columns(s.custody.clone());
        assert!(matches!(
            s.reconstruct().expect("reconstruct call"),
            DataColumnReconstructionResult::NotStarted("all sampling columns received")
        ));
    }

    /// Envelope + 50% of sampling columns → reconstruction recovers the rest, the entry flips
    /// to `Available`, and the cache holds every sampling column.
    #[tokio::test]
    async fn reconstruction_success_fills_missing_columns() {
        let s = setup(NodeCustodyType::Supernode);
        s.put_envelope();
        let sampling_count = s.custody.len();
        let half = sampling_count / 2;
        s.put_columns(s.custody.iter().take(half).cloned().collect());
        assert_eq!(s.cached_indexes().len(), half);

        let result = s.reconstruct().expect("reconstruction must succeed");
        let (availability, _recovered) = match result {
            DataColumnReconstructionResult::Success(inner) => inner,
            other => panic!("expected Success, got {other:?}"),
        };
        assert_available(availability);
        assert_eq!(s.cached_indexes().len(), sampling_count);
    }

    // ─── Tier 3: invariants ─────────────────────────────────────────────────

    /// `get_data_columns` and `cached_data_column_indexes` must agree on which columns are
    /// complete. Drift between these two would corrupt the DB on import.
    #[tokio::test]
    async fn cached_columns_match_completed_indexes() {
        let mut s = setup(NodeCustodyType::Fullnode);
        let last = s.custody.pop().expect("non-empty custody");

        let assert_lengths_match = |s: &Setup| {
            let indexes_len = s.cached_indexes().len();
            let sidecars_len = s.cache.get_data_columns(s.block_root).expect("entry").len();
            assert_eq!(indexes_len, sidecars_len);
        };

        s.put_columns(s.custody.clone());
        assert_lengths_match(&s);

        s.put_columns(vec![last]);
        assert_lengths_match(&s);
    }

    // ────────── Gloas partial column merge ─────────────────────────────────
    //
    // `merge_partial_data_columns` accumulates cells from partial (incomplete) columns until each
    // column has a cell for every expected blob. These tests drive that state machine directly.

    /// Build a Gloas KZG-verified custody partial column for `index` carrying cells at the `present`
    /// blob indices. Cell contents are irrelevant: the cache keys cells by blob index and never
    /// re-verifies them on merge.
    fn gloas_partial(
        block_root: Hash256,
        slot: Slot,
        index: ColumnIndex,
        total_blobs: usize,
        present: &[usize],
    ) -> KzgVerifiedCustodyPartialDataColumnGloas<E> {
        let mut bitmap = CellBitmap::<E>::with_capacity(total_blobs).unwrap();
        for &i in present {
            bitmap.set(i, true).unwrap();
        }
        let column: ProgressiveVariableList<_> =
            present.iter().map(|_| Cell::<E>::default()).collect();
        let kzg_proofs: ProgressiveVariableList<_> =
            present.iter().map(|_| KzgProof::empty()).collect();
        KzgVerifiedCustodyPartialDataColumnGloas::from_cached(Arc::new(PartialDataColumnGloas {
            block_root,
            slot,
            index,
            sidecar: PartialDataColumnSidecarGloas {
                cells_present_bitmap: bitmap,
                column,
                kzg_proofs,
            },
        }))
    }

    /// Two partial arrivals for the same column complete it: the first (one cell of two expected) is
    /// `MissingComponents` with no full column; the second fills the gap and yields one full column.
    #[tokio::test]
    async fn merge_partial_columns_completes_column_across_arrivals() {
        let s = setup_with(NodeCustodyType::Fullnode, NumBlobs::Number(2));
        let slot = s.cache.get_bid(&s.block_root).expect("bid").message.slot;

        // First arrival: column 0 carries only blob 0's cell — incomplete (1 of 2 expected).
        let first = gloas_partial(s.block_root, slot, 0, 2, &[0]);
        let (availability, result) = s
            .cache
            .merge_partial_data_columns(s.block_root, &[first])
            .expect("merge");
        assert_missing(availability);
        assert_eq!(result.added_cells, 1);
        assert!(result.full_columns.is_empty(), "column not yet complete");
        assert!(!s.cache.is_column_complete(&s.block_root, 0));

        // Re-merging blob 0 while the column is still incomplete adds nothing.
        let duplicate = gloas_partial(s.block_root, slot, 0, 2, &[0]);
        let (_availability, result) = s
            .cache
            .merge_partial_data_columns(s.block_root, &[duplicate])
            .expect("merge");
        assert_eq!(result.added_cells, 0);

        // Second arrival: column 0 gains blob 1's cell — now complete.
        let second = gloas_partial(s.block_root, slot, 0, 2, &[1]);
        let (_availability, result) = s
            .cache
            .merge_partial_data_columns(s.block_root, &[second])
            .expect("merge");
        assert_eq!(result.added_cells, 1);
        assert_eq!(result.full_columns.len(), 1, "column 0 becomes complete");
        assert_eq!(result.full_columns[0].index(), 0);
        assert!(s.cache.is_column_complete(&s.block_root, 0));
    }
}
