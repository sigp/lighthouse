use crate::data_availability_checker_v2::pending_components_cache::{
    DataAvailabilityCheckerInner, ReconstructColumnsDecision,
};

use crate::data_availability_checker::AvailabilityCheckError;
use crate::payload_envelope_verification::{
    AvailabilityPendingExecutedEnvelope, AvailableExecutedEnvelope,
};
use crate::{BeaconChain, BeaconChainTypes, CustodyContext, metrics};
use kzg::Kzg;
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{debug, error, instrument, trace};
use types::{
    BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, Slot,
};

mod payload_envelope_cache;
mod pending_components_cache;

use crate::data_column_verification::{
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
    verify_kzg_for_data_column_list,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
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
            Self::Available(data) => todo!(),
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
    availability_cache: Arc<DataAvailabilityCheckerInner<T>>,
    #[allow(dead_code)]
    slot_clock: T::SlotClock,
    kzg: Arc<Kzg>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        slot_clock: T::SlotClock,
        kzg: Arc<Kzg>,
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        let inner = DataAvailabilityCheckerInner::new(
            OVERFLOW_LRU_CAPACITY_NON_ZERO,
            custody_context.clone(),
            spec.clone(),
        )?;
        Ok(Self {
            availability_cache: Arc::new(inner),
            slot_clock,
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
        self.availability_cache.peek_data_columns(block_root)
    }

    /// Returns the indices of cached data columns for the given block root.
    #[instrument(skip_all, level = "trace")]
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>> {
        self.availability_cache
            .peek_pending_components(block_root, |components| {
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
        self.availability_cache
            .peek_pending_components(block_root, |components| {
                components.is_some_and(|components| {
                    let cached_column_opt = components.get_cached_data_column(*data_column.index());
                    cached_column_opt.is_some_and(|cached| *cached == *data_column)
                })
            })
    }

    pub fn put_executed_payload_envelope(
        &self,
        executed_envelope: AvailabilityPendingExecutedEnvelope<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_executed_payload_envelope(executed_envelope)
    }

    pub fn put_pre_executed_payload_envelope(
        &self,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        self.availability_cache
            .put_pre_executed_payload_envelope(envelope, source)
    }

    pub fn remove_pre_executed_payload_envelope(&self, block_root: &Hash256) {
        self.availability_cache
            .remove_pre_executed_envelope(block_root);
    }

    /// Insert RPC custody columns and check if the payload becomes available.
    #[instrument(skip_all, level = "trace")]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Attributes fault to the specific peer that sent an invalid column
        let kzg_verified_columns =
            KzgVerifiedDataColumn::from_batch_with_scoring(custody_columns, &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;

        // Filter out columns that aren't required for custody for this slot
        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self
            .custody_context
            .sampling_columns_for_epoch(epoch, &self.spec);
        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.availability_cache
            .put_kzg_verified_data_columns(block_root, verified_custody_columns)
    }

    /// Check if we've cached other data columns for this block root. If it satisfies the custody
    /// requirement, return the `Availability::Available` variant. Otherwise cache the data column sidecar.
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

        self.availability_cache
            .put_kzg_verified_data_columns(block_root, custody_columns)
    }

    #[instrument(skip_all, level = "trace")]
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        custody_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_kzg_verified_data_columns(block_root, custody_columns)
    }

    #[instrument(skip_all, level = "debug")]
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        let verified_data_columns = match self
            .availability_cache
            .check_and_set_reconstruction_started(block_root)
        {
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
            self.availability_cache
                .handle_reconstruction_failure(block_root);
            metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES);
            AvailabilityCheckError::ReconstructColumnsError(e)
        })?;

        // Check indices from cache again to make sure we don't publish components we've already received.
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

        // We only need to import and publish columns that we need to sample
        // and columns that we haven't already received
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

        self.availability_cache
            .put_kzg_verified_data_columns(*block_root, data_columns_to_import_and_publish.clone())
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

    /// Verifies KZG commitments for data columns.
    pub fn verify_kzg_for_data_columns(
        &self,
        data_columns: &DataColumnSidecarList<T::EthSpec>,
    ) -> Result<(), AvailabilityCheckError> {
        if !data_columns.is_empty() {
            verify_kzg_for_data_column_list(data_columns.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;
        }
        Ok(())
    }

    /// Insert an execution payload bid into the cache and check if data becomes available.
    pub fn put_bid(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache.put_bid(block_root, bid)
    }

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            block_cache_size: self.availability_cache.block_cache_size(),
        }
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
        let overflow_cache = chain
            .data_availability_checker
            .v2()
            .availability_cache
            .clone();
        executor.spawn(
            async move { availability_cache_maintenance_service(chain, overflow_cache).await },
            "availability_cache_service",
        );
    } else {
        trace!("Gloas fork not configured, not starting availability cache maintenance service");
    }
}

async fn availability_cache_maintenance_service<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    overflow_cache: Arc<DataAvailabilityCheckerInner<T>>,
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

                if let Err(e) = overflow_cache.do_maintenance(cutoff_epoch) {
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
