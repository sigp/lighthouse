//! This module builds out the data availability cache for Gloas. When a beacon block is received
//! over gossip/p2p we insert its payload into this cache, keyed by block root. As soon as the bid
//! is received we can begin using it to verify data columns.
//!
//! When a payload envelope is received over gossip/p2p we first insert it as a pre-executed envelope. A separate
//! thread eventually executes the payload envelope against the EL. Assuming the payload is executed succesfully
//! the envelope is updated in the cache from `PreExecuted` -> `Executed`. Once all required custody columns
//! have been kzg verified and the envelope has been executed we can import the envelope into fork choice and store it to disk.
//!
//! Note that the block must have arrived before the envelope for the envelope to pass upstream verification checks and reach this cache.
//! However data columns can potentially arrive before the block.
//!
//!
//! SignedBeaconBlock
//!          |
//!          | -> SignedExecutionPayloadBid
//!
//!
//! DataColumnSidecarList
//!          |
//!          | -> Perform data column verification against `SignedExecutionPayloadBid`
//!          │           │   
//!          │           ▼
//!          | -> KzgVerifiedCustodyDataColumn
//!   
//!
//! SignedExecutionPayloadEnvelope                                                                                          
//!          │                                                                                                                                         
//!          | -> CachedPayloadEnvelope::PreExecution                                                         
//!          │           │                                                                                                                             
//!          │           ▼                                                                                                                             
//!          | -> AvailabilityPendingExecutedEnvelope
//!          │           │                                                                                                                             
//!          │           ▼                                                                         
//!          │ -> CachedPayloadEnvelope::Executed                                                                                                    
//!          │           │                                                                                                                             
//!          │           ▼                                                                                                                             
//!          | -> AvailableExecutedEnvelope  (all columns present, payload executed against the EL, ready to import)

use crate::data_availability_checker::AvailabilityCheckError;
use crate::payload_envelope_verification::{
    AvailabilityPendingExecutedEnvelope, AvailableExecutedEnvelope,
};
use crate::{BeaconChain, BeaconChainTypes, CustodyContext, metrics};
use kzg::Kzg;
use lru::LruCache;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{Span, debug, error, instrument, trace};
use types::{
    BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch,
    EthSpec, Hash256, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, Slot,
};

mod pending_components;

use crate::data_column_verification::{
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
use pending_components::{PendingComponents, ReconstructColumnsDecision};
use types::new_non_zero_usize;

/// The LRU Cache stores `PendingComponents`, which store the block root, the execution payload bid, and its associated column data.
/// The execution payload bid stores the kzg commitments which we use to verify against incoming column data.
/// Setting this to 32 keeps memory usage reasonable.
///
/// `PendingComponents` are now never removed from the cache manually and are only removed via LRU
/// eviction to prevent race conditions (#7961), so we expect this cache to be full all the time.
const OVERFLOW_LRU_CAPACITY_NON_ZERO: NonZeroUsize = new_non_zero_usize(32);

/// Represents available data for a payload - its block root and its data columns.
pub type AvailableData<E> = (Hash256, DataColumnSidecarList<E>);

/// This type is returned after adding a bid / column to the `DataAvailabilityChecker`.
///
/// Indicates if the payloads data is fully `Available` or if we need more columns.
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedEnvelope<E>>),
}

pub enum PayloadEnvelopeProcessingStatus<E: EthSpec> {
    /// Envelope is not in any pre-import cache. Envelope may be in the data-base or in the fork-choice.
    Unknown,
    /// Envelope is currently processing but not yet validated.
    NotValidated(Arc<SignedExecutionPayloadEnvelope<E>>, BlockImportSource),
    /// Envelope is fully valid, but not yet imported. It's cached in the da_checker while awaiting
    /// missing envelope components.
    ExecutionValidated(Arc<SignedExecutionPayloadEnvelope<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            // TODO(gloas) fix success case
            Self::Available(envelope) => {
                write!(f, "Available({:?})", envelope.import_data.block_root)
            }
        }
    }
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);

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
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    availability_cache: RwLock<LruCache<Hash256, PendingComponents<T::EthSpec>>>,
    kzg: Arc<Kzg>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        kzg: Arc<Kzg>,
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            availability_cache: RwLock::new(LruCache::new(OVERFLOW_LRU_CAPACITY_NON_ZERO)),
            kzg,
            custody_context,
            spec,
        })
    }

    pub fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>> {
        &self.custody_context
    }

    /// Returns all cached data columns for the given block root, if any.
    #[instrument(skip_all, level = "trace")]
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.peek_pending_components(&block_root, |components| {
            components.map(|c| {
                c.verified_data_columns
                    .iter()
                    .map(|col| col.clone_arc())
                    .collect()
            })
        })
    }

    /// Returns the indices of cached data columns for the given block root.
    #[instrument(skip_all, level = "trace")]
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>> {
        self.peek_pending_components(block_root, |components| {
            components.map(|components| components.get_cached_data_columns_indices())
        })
    }

    /// Checks if a specific data column is cached for the given block root.
    #[instrument(skip_all, level = "trace")]
    pub fn is_data_column_cached(
        &self,
        block_root: &Hash256,
        data_column: &DataColumnSidecar<T::EthSpec>,
    ) -> bool {
        self.peek_pending_components(block_root, |components| {
            components.is_some_and(|components| {
                let cached_column_opt = components.get_cached_data_column(*data_column.index());
                cached_column_opt.is_some_and(|cached| *cached == *data_column)
            })
        })
    }

    /// Returns the envelope processing status for the given `block_root`.
    pub fn get_envelope_processing_status(
        &self,
        block_root: &Hash256,
    ) -> Option<PayloadEnvelopeProcessingStatus<T::EthSpec>> {
        self.peek_pending_components(block_root, |components| {
            components.and_then(|c| {
                c.envelope.as_ref().map(|envelope| match envelope {
                    pending_components::CachedPayloadEnvelope::PreExecution(e, source) => {
                        PayloadEnvelopeProcessingStatus::NotValidated(e.clone(), *source)
                    }
                    pending_components::CachedPayloadEnvelope::Executed(e) => {
                        PayloadEnvelopeProcessingStatus::ExecutionValidated(e.envelope.clone())
                    }
                })
            })
        })
    }

    /// Insert an executed payload envelope into the cache and performs an availability check
    pub fn put_executed_payload_envelope(
        &self,
        executed_envelope: AvailabilityPendingExecutedEnvelope<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = executed_envelope.envelope.epoch();
        let beacon_block_root = executed_envelope.envelope.beacon_block_root();
        let pending_components =
            self.update_or_insert_pending_components(beacon_block_root, |pending_components| {
                pending_components.insert_executed_payload_envelope(executed_envelope);
                Ok(())
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "executed envelope",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(beacon_block_root, pending_components, num_expected_columns)
    }

    /// Insert a pre executed payload envelope in the cache
    pub fn put_pre_executed_payload_envelope(
        &self,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        let epoch = envelope.epoch();
        let beacon_block_root = envelope.beacon_block_root();
        let pending_components =
            self.update_or_insert_pending_components(beacon_block_root, |pending_components| {
                pending_components.insert_pre_executed_payload_envelope(envelope, source);
                Ok(())
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "pre executed payload envelope",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        Ok(())
    }

    /// Removes a pre-executed envelope from the cache.
    /// This does NOT remove an existing executed envelope.
    pub fn remove_pre_executed_payload_envelope(&self, block_root: &Hash256) {
        if let Some(PayloadEnvelopeProcessingStatus::NotValidated(_, _)) =
            self.get_envelope_processing_status(block_root)
        {
            // If the envelope is execution invalid, this status is permanent and idempotent to this
            // block_root. We drop its components (e.g. columns) because they will never be useful.
            self.availability_cache.write().pop(block_root);
        }
    }

    /// Insert an execution payload bid into the cache.
    pub fn put_bid(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());

        let pending_components =
            self.update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.insert_bid(bid);
                Ok(())
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "bid",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(block_root, pending_components, num_expected_columns)
    }

    /// Perform KZG verification on RPC custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available.
    #[instrument(skip_all, level = "trace")]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let kzg_verified_columns =
            KzgVerifiedDataColumn::from_batch_with_scoring(custody_columns, &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;

        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self
            .custody_context
            .sampling_columns_for_epoch(epoch, &self.spec);
        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, verified_custody_columns)
    }

    /// Perform KZG verification on gossip verified custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available
    #[instrument(skip_all, level = "trace")]
    pub fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        slot: Slot,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self
            .custody_context
            .sampling_columns_for_epoch(epoch, &self.spec);
        let custody_columns = data_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, custody_columns)
    }

    /// Insert KZG verified columns into the cache.
    /// After insertion check if the envelope becomes available.
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        kzg_verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut kzg_verified_data_columns = kzg_verified_data_columns.into_iter().peekable();
        let Some(epoch) = kzg_verified_data_columns
            .peek()
            .map(|verified_col| verified_col.as_data_column().epoch())
        else {
            return Ok(Availability::MissingComponents(block_root));
        };

        let pending_components = self
            .update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.merge_data_columns(kzg_verified_data_columns)
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "data_columns",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(block_root, pending_components, num_expected_columns)
    }

    #[instrument(skip_all, level = "debug")]
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        let verified_data_columns = match self.check_and_set_reconstruction_started(block_root) {
            ReconstructColumnsDecision::Yes(verified_data_columns) => verified_data_columns,
            ReconstructColumnsDecision::No(reason) => {
                return Ok(DataColumnReconstructionResult::NotStarted(reason));
            }
        };

        metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS);
        let timer = metrics::start_timer(&metrics::DATA_AVAILABILITY_RECONSTRUCTION_TIME);

        let all_data_columns = KzgVerifiedCustodyDataColumn::reconstruct_columns(
            &self.kzg,
            &verified_data_columns,
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

        let Some(existing_column_indices) = self.cached_data_column_indexes(block_root) else {
            return Err(AvailabilityCheckError::Unexpected(
                "block no longer exists in the data availability checker".to_string(),
            ));
        };

        let Some(slot) = all_data_columns.first().map(|d| d.as_data_column().slot()) else {
            return Ok(DataColumnReconstructionResult::RecoveredColumnsNotImported(
                "No new columns to import and publish",
            ));
        };

        let columns_to_sample = self
            .custody_context()
            .sampling_columns_for_epoch(slot.epoch(T::EthSpec::slots_per_epoch()), &self.spec);

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

        self.put_kzg_verified_custody_data_columns(
            *block_root,
            data_columns_to_import_and_publish.clone(),
        )
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

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            block_cache_size: self.block_cache_size(),
        }
    }

    /// Number of pending component entries in memory in the cache.
    pub fn block_cache_size(&self) -> usize {
        self.availability_cache.read().len()
    }

    // ── Internal helpers ──

    fn check_availability(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
        num_expected_columns: usize,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(available_envelope) = pending_components.make_available(num_expected_columns)? {
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

    /// Updates or inserts a new `PendingComponents` if it doesn't exist, and then apply the
    /// `update_fn` while holding the write lock.
    ///
    /// Once the update is complete, the write lock is downgraded and a read guard with a
    /// reference of the updated `PendingComponents` is returned.
    fn update_or_insert_pending_components<F>(
        &self,
        block_root: Hash256,
        update_fn: F,
    ) -> Result<MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>, AvailabilityCheckError>
    where
        F: FnOnce(&mut PendingComponents<T::EthSpec>) -> Result<(), AvailabilityCheckError>,
    {
        let mut write_lock = self.availability_cache.write();

        {
            let pending_components = write_lock.get_or_insert_mut(block_root, || {
                PendingComponents::empty(block_root, self.spec.clone())
            });
            update_fn(pending_components)?
        }

        RwLockReadGuard::try_map(RwLockWriteGuard::downgrade(write_lock), |cache| {
            cache.peek(&block_root)
        })
        .map_err(|_| {
            AvailabilityCheckError::Unexpected("pending components should exist".to_string())
        })
    }

    fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.availability_cache.read().peek(block_root))
    }

    /// Check whether data column reconstruction should be attempted.
    fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.availability_cache.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            return ReconstructColumnsDecision::No("block already imported");
        };

        let Some(epoch) = pending_components
            .verified_data_columns
            .first()
            .map(|c| c.as_data_column().epoch())
        else {
            return ReconstructColumnsDecision::No("not enough columns");
        };

        let total_column_count = T::EthSpec::number_of_columns();
        let sampling_column_count = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);
        let received_column_count = pending_components.verified_data_columns.len();

        if pending_components.reconstruction_started {
            return ReconstructColumnsDecision::No("already started");
        }
        if received_column_count >= sampling_column_count {
            return ReconstructColumnsDecision::No("all sampling columns received");
        }
        if received_column_count < total_column_count / 2 {
            return ReconstructColumnsDecision::No("not enough columns");
        }

        pending_components.reconstruction_started = true;
        ReconstructColumnsDecision::Yes(pending_components.verified_data_columns.clone())
    }

    /// This could mean some invalid data columns made it through to the `DataAvailabilityChecker`.
    /// In this case, we remove all data columns in `PendingComponents`, reset reconstruction
    /// status so that we can attempt to retrieve columns from peers again.
    fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        if let Some(pending_components_mut) = self.availability_cache.write().get_mut(block_root) {
            pending_components_mut.verified_data_columns = vec![];
            pending_components_mut.reconstruction_started = false;
        }
    }

    fn get_num_expected_columns(&self, epoch: Epoch) -> usize {
        self.custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec)
    }

    /// Maintain the cache by removing entries older than the cutoff epoch.
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        let mut write_lock = self.availability_cache.write();
        let mut keys_to_remove = vec![];
        for (key, value) in write_lock.iter() {
            if let Some(epoch) = value.epoch()
                && epoch < cutoff_epoch
            {
                keys_to_remove.push(*key);
            }
        }
        for key in keys_to_remove {
            write_lock.pop(&key);
        }

        Ok(())
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub block_cache_size: usize,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    if chain.spec.gloas_fork_epoch.is_some() {
        let da_checker = chain.data_availability_checker.v2().clone();
        executor.spawn(
            async move { availability_cache_maintenance_service(chain, da_checker).await },
            "availability_cache_service",
        );
    } else {
        trace!("Gloas fork not configured, not starting availability cache maintenance service");
    }
}

async fn availability_cache_maintenance_service<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    da_checker: Arc<DataAvailabilityChecker<T>>,
) {
    let epoch_duration = chain.slot_clock.slot_duration() * T::EthSpec::slots_per_epoch() as u32;
    loop {
        match chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
        {
            Some(duration) => {
                // this service should run 3/4 of the way through the epoch
                let additional_delay = (epoch_duration * 3) / 4;
                tokio::time::sleep(duration + additional_delay).await;

                let Some(gloas_fork_epoch) = chain.spec.gloas_fork_epoch else {
                    // shutdown service if gloas fork epoch not set
                    break;
                };

                debug!("Availability cache maintenance service firing");
                let Some(current_epoch) = chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                else {
                    continue;
                };

                if current_epoch < gloas_fork_epoch {
                    // we are not in gloas yet
                    continue;
                }

                let finalized_epoch = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .finalized_checkpoint()
                    .epoch;

                let Some(min_epochs_for_blobs) = chain
                    .spec
                    .min_epoch_data_availability_boundary(current_epoch)
                else {
                    // Shutdown service if deneb fork epoch not set.
                    break;
                };

                // any data belonging to an epoch before this should be pruned
                let cutoff_epoch = std::cmp::max(finalized_epoch + 1, min_epochs_for_blobs);

                if let Err(e) = da_checker.do_maintenance(cutoff_epoch) {
                    error!(error = ?e,"Failed to maintain availability cache");
                }
            }
            None => {
                error!("Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                tokio::time::sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
}

#[cfg(test)]
mod data_availability_checker_tests {
    use super::*;

    use crate::block_verification::PayloadVerificationOutcome;
    use crate::data_column_verification::{KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn};
    use crate::payload_envelope_verification::EnvelopeImportData;
    use crate::test_utils::{
        NumBlobs, generate_data_column_indices_rand_order, generate_rand_block_and_data_columns,
        test_spec,
    };
    use crate::{
        custody_context::NodeCustodyType,
        test_utils::{BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::create_test_tracing_subscriber;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use store::{HotColdDB, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use types::{
        BeaconState, ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequests, ForkName,
        FullPayload, MinimalEthSpec, SignedBeaconBlock, Slot,
    };

    type E = MinimalEthSpec;

    const LOW_VALIDATOR_COUNT: usize = 32;

    fn gloas_spec<E: EthSpec>() -> Arc<ChainSpec> {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(0));
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.electra_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = Some(Epoch::new(0));
        Arc::new(spec)
    }

    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: Arc<ChainSpec>,
    ) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
        let hot_path = db_path.path().join("hot_db");
        let cold_path = db_path.path().join("cold_db");
        let blobs_path = db_path.path().join("blobs_db");
        let config = StoreConfig::default();

        HotColdDB::open(
            &hot_path,
            &cold_path,
            &blobs_path,
            |_, _, _| Ok(()),
            config,
            spec,
        )
        .expect("disk store should initialize")
    }

    async fn get_gloas_chain<E: EthSpec>(
        db_path: &TempDir,
    ) -> BeaconChainHarness<DiskHarnessType<E>> {
        let spec = gloas_spec::<E>();

        let chain_store = get_store_with_spec::<E>(db_path, spec.clone());
        let validators_keypairs =
            types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
        BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build()
    }

    async fn setup_harness_and_cache<T>() -> (
        BeaconChainHarness<DiskHarnessType<E>>,
        Arc<DataAvailabilityChecker<T>>,
        TempDir,
    )
    where
        T: BeaconChainTypes<
                HotStore = BeaconNodeBackend<E>,
                ColdStore = BeaconNodeBackend<E>,
                EthSpec = E,
            >,
    {
        create_test_tracing_subscriber();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_gloas_chain::<E>(&chain_db_path).await;
        let spec = harness.spec.clone();
        let custody_context = Arc::new(CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        ));

        let cache = Arc::new(
            DataAvailabilityChecker::<T>::new(
                harness.chain.kzg.clone(),
                custody_context,
                spec.clone(),
            )
            .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    fn is_gloas_enabled() -> bool {
        let spec = test_spec::<E>();
        spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled()
    }

    #[tokio::test]
    async fn test_cache_creation() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>().await;
        assert_eq!(cache.block_cache_size(), 0);
    }

    // TODO(gloas): Add tests for `put_rpc_custody_columns` and `put_gossip_verified_data_columns`
    // once the Gloas harness can produce KZG-valid columns. These wrappers add KZG verification
    // and custody column filtering on top of `put_kzg_verified_custody_data_columns`.

    #[tokio::test]
    async fn test_put_columns_creates_pending_components() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(1) // Just take one column for the test
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        // Put columns into cache
        let result = cache.put_kzg_verified_custody_data_columns(block_root, verified_columns);
        assert!(result.is_ok());

        // Check that pending components were created
        assert_eq!(cache.block_cache_size(), 1);

        // Verify columns are cached
        let cached_indices = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns_indices())
        });
        assert!(cached_indices.is_some());
        assert_eq!(cached_indices.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_column_deduplication() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Get the first column
        let first_column = data_columns.first().cloned().expect("should have column");
        let column_index = *first_column.index();

        let verified_column = KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(first_column.clone()),
        );

        // Insert the same column twice
        cache
            .put_kzg_verified_custody_data_columns(block_root, vec![verified_column.clone()])
            .expect("should put column");

        cache
            .put_kzg_verified_custody_data_columns(block_root, vec![verified_column])
            .expect("should put column again");

        // Check that we still only have one column (deduplicated)
        let cached_indices = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns_indices())
        });
        assert!(cached_indices.is_some());
        let indices = cached_indices.unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0], column_index);
    }

    #[tokio::test]
    async fn test_columns_without_block_not_available() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add all columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let result = cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Without a bid, should still be missing components
        assert!(matches!(result, Availability::MissingComponents(_)));
    }

    /// Helper to create a test bid with the given block root and kzg commitments from a block.
    fn make_test_bid<E: EthSpec>(
        block: &SignedBeaconBlock<E, FullPayload<E>>,
    ) -> Arc<SignedExecutionPayloadBid<E>> {
        let bid = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .expect("gloas block should have bid")
            .clone();
        Arc::new(bid)
    }

    fn make_test_signed_envelope(block_root: Hash256) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        Arc::new(SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayloadGloas::default(),
                execution_requests: ExecutionRequests::default(),
                builder_index: 0,
                beacon_block_root: block_root,
                slot: Slot::new(0),
                state_root: Hash256::ZERO,
            },
            signature: bls::Signature::infinity().expect("should create infinity sig"),
        })
    }

    fn make_test_executed_envelope(block_root: Hash256) -> AvailabilityPendingExecutedEnvelope<E> {
        AvailabilityPendingExecutedEnvelope {
            envelope: make_test_signed_envelope(block_root),
            import_data: EnvelopeImportData {
                block_root,
                post_state: Box::new(BeaconState::new(0, Default::default(), &gloas_spec::<E>())),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
            },
        }
    }

    #[tokio::test]
    async fn test_full_availability_flow() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();
        let bid = make_test_bid(&block);

        cache.put_bid(block_root, bid).expect("should put bid");
        assert!(matches!(
            cache.put_bid(block_root, make_test_bid(&block)),
            Ok(Availability::MissingComponents(_))
        ));

        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let result = cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        assert!(matches!(result, Availability::MissingComponents(_)));

        // Insert pre-executed envelope first
        cache
            .put_pre_executed_payload_envelope(
                make_test_signed_envelope(block_root),
                BlockImportSource::Gossip,
            )
            .expect("should put pre-executed envelope");

        let status = cache.get_envelope_processing_status(&block_root);
        assert!(matches!(
            status,
            Some(PayloadEnvelopeProcessingStatus::NotValidated(..))
        ));

        // Upgrade to executed envelope (after EL validation)
        let executed_envelope = make_test_executed_envelope(block_root);
        let result = cache
            .put_executed_payload_envelope(executed_envelope)
            .expect("should put executed envelope");

        assert!(
            matches!(result, Availability::Available(_)),
            "expected Available, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_zero_blob_bid_immediately_available() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        // Generate a block with 0 blobs — bid will have empty commitments
        let (block, _data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(0),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();
        let bid = make_test_bid(&block);

        // Insert bid (no blobs expected)
        cache.put_bid(block_root, bid).expect("should put bid");

        // Insert executed envelope — should become available immediately (no columns needed)
        let executed_envelope = make_test_executed_envelope(block_root);
        let result = cache
            .put_executed_payload_envelope(executed_envelope)
            .expect("should put executed envelope");

        assert!(
            matches!(result, Availability::Available(_)),
            "zero-blob bid should be immediately available, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_columns_arrive_before_bid() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Columns arrive before bid
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let result = cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");
        assert!(matches!(result, Availability::MissingComponents(_)));

        let bid = make_test_bid(&block);
        let result = cache.put_bid(block_root, bid).expect("should put bid");
        assert!(matches!(result, Availability::MissingComponents(_)));

        let executed_envelope = make_test_executed_envelope(block_root);
        let result = cache
            .put_executed_payload_envelope(executed_envelope)
            .expect("should put executed envelope");

        assert!(
            matches!(result, Availability::Available(_)),
            "expected Available after all components inserted, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_pre_executed_envelope_not_available() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Insert bid + all columns
        cache
            .put_bid(block_root, make_test_bid(&block))
            .expect("should put bid");

        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();
        cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Insert pre-executed envelope (not yet validated by EL)
        cache
            .put_pre_executed_payload_envelope(
                make_test_signed_envelope(block_root),
                BlockImportSource::Gossip,
            )
            .expect("should put pre-executed envelope");

        // Should NOT be available — envelope not executed yet
        let status = cache.get_envelope_processing_status(&block_root);
        assert!(matches!(
            status,
            Some(PayloadEnvelopeProcessingStatus::NotValidated(..))
        ));
    }

    #[tokio::test]
    async fn test_remove_pre_executed_envelope() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let block_root = Hash256::random();

        // Insert pre-executed envelope
        cache
            .put_pre_executed_payload_envelope(
                make_test_signed_envelope(block_root),
                BlockImportSource::Gossip,
            )
            .expect("should put pre-executed envelope");

        // Verify it's there
        assert!(cache.get_envelope_processing_status(&block_root).is_some());

        // Remove it
        cache.remove_pre_executed_payload_envelope(&block_root);

        // Should be gone
        let status = cache.get_envelope_processing_status(&block_root);
        assert!(status.is_none());
    }

    #[tokio::test]
    async fn test_remove_pre_executed_does_not_remove_executed() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let block_root = Hash256::random();

        // Insert executed envelope
        let executed_envelope = make_test_executed_envelope(block_root);
        cache
            .put_executed_payload_envelope(executed_envelope)
            .expect("should put executed envelope");

        // Try to remove as pre-executed — should be a no-op
        cache.remove_pre_executed_payload_envelope(&block_root);

        // Should still be there as executed
        let status = cache.get_envelope_processing_status(&block_root);
        assert!(matches!(
            status,
            Some(PayloadEnvelopeProcessingStatus::ExecutionValidated(..))
        ));
    }

    #[tokio::test]
    async fn test_reconstruction_started_flag() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add some columns (not enough for reconstruction threshold)
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(10) // Not enough for reconstruction
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Check reconstruction decision - should say "not enough columns"
        let decision = cache.check_and_set_reconstruction_started(&block_root);
        assert!(matches!(decision, ReconstructColumnsDecision::No(_)));
    }

    #[tokio::test]
    async fn test_handle_reconstruction_failure_clears_columns() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add some columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(5)
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Verify columns are cached
        let cached_count = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.verified_data_columns.len())
        });
        assert_eq!(cached_count, Some(5));

        // Handle reconstruction failure
        cache.handle_reconstruction_failure(&block_root);

        // Verify columns are cleared
        let cached_count_after = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.verified_data_columns.len())
        });
        assert_eq!(cached_count_after, Some(0));
    }

    #[tokio::test]
    async fn test_maintenance_removes_old_entries() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>().await;

        // Run maintenance with a future cutoff epoch
        let cutoff_epoch = Epoch::new(100);
        cache
            .do_maintenance(cutoff_epoch)
            .expect("maintenance should succeed");

        // Cache should still be empty since we didn't add anything with an epoch
        assert_eq!(cache.block_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_peek_data_columns() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // No columns yet
        assert!(cache.get_data_columns(block_root).is_none());

        // Add columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(3)
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Now columns should be returned
        let peeked = cache.get_data_columns(block_root);
        assert!(peeked.is_some());
        assert_eq!(peeked.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        // LRU capacity is 32 (OVERFLOW_LRU_CAPACITY_NON_ZERO). Insert 33 entries.
        let mut roots = Vec::new();
        for _ in 0..33 {
            let block_root = Hash256::random();
            roots.push(block_root);
            let col = data_columns.first().cloned().expect("should have column");
            let verified = vec![KzgVerifiedCustodyDataColumn::from_asserted_custody(
                KzgVerifiedDataColumn::__new_for_testing(col),
            )];
            cache
                .put_kzg_verified_custody_data_columns(block_root, verified)
                .expect("should put columns");
        }

        assert_eq!(cache.block_cache_size(), 32);
        assert!(cache.get_data_columns(roots[0]).is_none());
        assert!(cache.get_data_columns(*roots.last().unwrap()).is_some());
    }

    #[tokio::test]
    async fn test_maintenance_prunes_old_entries() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Insert bid (gives the entry an epoch via the bid's slot)
        cache
            .put_bid(block_root, make_test_bid(&block))
            .expect("should put bid");

        let col = data_columns.first().cloned().expect("should have column");
        let verified = vec![KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(col),
        )];
        cache
            .put_kzg_verified_custody_data_columns(block_root, verified)
            .expect("should put columns");

        assert_eq!(cache.block_cache_size(), 1);

        // Maintenance with cutoff in the future should prune (bid slot=0 → epoch=0 < cutoff=100)
        cache
            .do_maintenance(Epoch::new(100))
            .expect("maintenance should succeed");

        assert_eq!(cache.block_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_double_reconstruction_prevented() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Insert all columns so reconstruction threshold is met
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Manually set reconstruction_started via check_and_set
        // For fullnode, sampling == all columns, so this returns No("all sampling columns received")
        // But we can set the flag manually to test the guard
        cache
            .availability_cache
            .write()
            .get_mut(&block_root)
            .expect("should exist")
            .reconstruction_started = true;

        let decision = cache.check_and_set_reconstruction_started(&block_root);
        assert!(
            matches!(decision, ReconstructColumnsDecision::No(reason) if reason == "already started"),
            "second reconstruction attempt should be prevented"
        );
    }

    #[tokio::test]
    async fn test_partial_columns_missing_components() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let (harness, cache, _path) = setup_harness_and_cache::<T>().await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Insert bid and executed envelope
        cache
            .put_bid(block_root, make_test_bid(&block))
            .expect("should put bid");

        let executed_envelope = make_test_executed_envelope(block_root);
        cache
            .put_executed_payload_envelope(executed_envelope)
            .expect("should put executed envelope");

        // Insert only 1 column (need 128 for fullnode)
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(1)
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let result = cache
            .put_kzg_verified_custody_data_columns(block_root, verified_columns)
            .expect("should put columns");

        assert!(
            matches!(result, Availability::MissingComponents(_)),
            "partial columns should not trigger availability"
        );
    }
}
