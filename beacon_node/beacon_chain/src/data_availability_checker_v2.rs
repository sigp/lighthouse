use crate::data_availability_checker_v2::overflow_lru_cache::{
    DataAvailabilityCheckerInner, ReconstructColumnsDecision,
};

use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_availability_router::DataColumnCache;
use crate::payload_verification_types::{
    AvailabilityPendingExecutedPayload, AvailableExecutedPayload, PayloadProcessStatus,
};
use crate::{BeaconChain, BeaconChainTypes, CustodyContext, metrics};
use educe::Educe;
use kzg::Kzg;
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tracing::{debug, error, instrument};
use types::{
    BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope, Slot,
};

mod overflow_lru_cache;

use crate::data_column_verification::{
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
    verify_kzg_for_data_column_list,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
use types::new_non_zero_usize;

/// The LRU Cache stores `PendingComponents`, which store payload and its associated column data:
///
/// With `MAX_BLOBS_PER_BLOCK` = 48 for exa,ple, the maximum size of data columns
/// in `PendingComponents` is ~12.29 MB. Setting this to 32 means the maximum size of the cache is
/// approximately 0.4 GB.
///
/// `PendingComponents` are now never removed from the cache manually are only removed via LRU
/// eviction to prevent race conditions (#7961), so we expect this cache to be full all the time.
const OVERFLOW_LRU_CAPACITY_NON_ZERO: NonZeroUsize = new_non_zero_usize(32);

/// Cache to hold fully valid data that can't be imported to fork-choice yet. After the Gloas hard-fork
/// beacon blocks can be immediately imported into fork choice. The execution payload is now separated out from
/// the beacon block. The payload envelope and data columns are received separately from the network. The block
/// is now always considered "available". Availability checks are now made on the payload and it is considered
/// "fully available" when the payload and all required columns are inserted into this cache.
///
/// Usually a payload becomes available on its slot within a second of receiving its first component
/// over gossip. However, a payload may never become available if a malicious proposer does not
/// publish its data, or there are network issues that prevent us from receiving it. If the payload
/// does not become available after some time we can safely forget about it. Consider these two
/// cases:
///
/// - Global unavailability: If nobody has received the payload components it's likely that the
///   builder never made the payload available. So we can safely forget about the payload as it will
///   never become available.
/// - Local unavailability: Some fraction of the network has received all payload components, but not us.
///   Some of our peers will eventually attest to a descendant of that block and lookup sync will
///   fetch its components. Therefore it's not strictly necessary to hold to the partially available
///   payload for too long as we can recover from other peers.
///
/// Even in periods of non-finality, the builder is expected to publish the payload's data
/// immediately. Because this cache only holds fully valid data, its capacity is bound to 1 block
/// per slot and fork: before inserting into this cache we check the proposer signature and correct
/// proposer. Having a capacity > 1 is an optimization to prevent sync lookup from having re-fetch
/// data during moments of unstable network conditions.
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    #[allow(dead_code)]
    complete_blob_backfill: bool,
    availability_cache: Arc<DataAvailabilityCheckerInner<T>>,
    #[allow(dead_code)]
    slot_clock: T::SlotClock,
    kzg: Arc<Kzg>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);

#[derive(Debug)]
pub enum DataColumnReconstructionResult<E: EthSpec> {
    Success(AvailabilityAndReconstructedColumns<E>),
    NotStarted(&'static str),
    RecoveredColumnsNotImported(&'static str),
}

/// This type is returned after adding a payload / column to the `DataAvailabilityChecker`.
///
/// Indicates if the payload is fully `Available` or if we need columns or payload
///  to "complete" the requirements for an `AvailablePayload`.
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedPayload<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(payload) => write!(f, "Available({:?})", payload.payload.block_root),
        }
    }
}

impl<T: BeaconChainTypes> DataColumnCache<T> for DataAvailabilityChecker<T> {
    type Availability = Availability<T::EthSpec>;
    type ReconstructionResult = DataColumnReconstructionResult<T::EthSpec>;

    /// Returns the custody context used by this checker.
    fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>> {
        &self.custody_context
    }

    /// Returns all cached data columns for the given block root, if any.
    #[instrument(skip_all, level = "trace")]
    fn get_data_columns(&self, block_root: Hash256) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.availability_cache.peek_data_columns(block_root)
    }

    /// Returns the indices of cached data columns for the given block root.
    #[instrument(skip_all, level = "trace")]
    fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>> {
        self.availability_cache
            .peek_pending_components(block_root, |components| {
                components.map(|components| components.get_cached_data_columns_indices())
            })
    }

    /// Checks if a specific data column is cached for the given block root.
    #[instrument(skip_all, level = "trace")]
    fn is_data_column_cached(
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

    /// Insert RPC custody columns and check if the block/payload becomes available.
    #[instrument(skip_all, level = "trace")]
    fn put_rpc_custody_columns(
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
        // This is required because `data_columns_by_root` requests the **latest** CGC that _may_
        // not be yet effective for data availability check, as CGC changes are only effecive from
        // a new epoch.
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

    /// Check if we've cached other data columns for this payload. If it satisfies the custody requirement and we also
    /// have a payload cached, return the `Availability` variant triggering payload import.
    /// Otherwise cache the data column sidecar.
    ///
    /// This should only accept gossip verified data columns, so we should not have to worry about dupes.
    #[instrument(skip_all, level = "trace")]
    fn put_gossip_verified_data_columns<O: ObservationStrategy>(
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
    fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        custody_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_kzg_verified_data_columns(block_root, custody_columns)
    }

    #[instrument(skip_all, level = "debug")]
    fn reconstruct_data_columns(
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
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        complete_blob_backfill: bool,
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
            complete_blob_backfill,
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

    /// Checks if the payload associated with the given block root is currently in the availability cache awaiting import because
    /// of missing components.
    ///
    /// Returns the cached payload wrapped in a `PayloadProcessStatus` enum if it exists.
    pub fn get_cached_payload(
        &self,
        block_root: &Hash256,
    ) -> Option<PayloadProcessStatus<T::EthSpec>> {
        self.availability_cache.get_cached_payload(block_root)
    }

    /// Check if we have all required columns for a payload. Returns `Availability` which has information
    /// about whether all components have been received or more are required.
    pub fn put_executed_payload(
        &self,
        executed_payload: AvailabilityPendingExecutedPayload<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_executed_payload(executed_payload)
    }

    /// Inserts a pre-execution payload into the cache.
    /// This does NOT override an existing executed payload.
    pub fn put_pre_execution_payload(
        &self,
        block_root: Hash256,
        payload: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        self.availability_cache
            .put_pre_execution_payload(block_root, payload, source)
    }

    /// Removes a pre-execution payload from the cache.
    /// This does NOT remove an existing executed payload.
    pub fn remove_payload_on_execution_error(&self, block_root: &Hash256) {
        self.availability_cache
            .remove_pre_execution_payload(block_root);
    }

    /// Verifies kzg commitments for an `AvailableBlock`.`
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_available_payload(
        &self,
        available_payload: &AvailablePayload<T::EthSpec>,
    ) -> Result<(), AvailabilityCheckError> {
        let block_data_required = self
            .custody_context
            .data_columns_required_for_payload(&available_payload.payload);
        match available_payload.data() {
            AvailablePayloadData::NoData => {
                if block_data_required {
                    return Err(AvailabilityCheckError::MissingCustodyColumns);
                }
            }
            AvailablePayloadData::DataColumns(data_columns) => {
                verify_kzg_for_data_column_list(data_columns.iter(), &self.kzg)
                    .map_err(AvailabilityCheckError::InvalidColumn)?;
            }
        }

        Ok(())
    }

    /// Performs batch kzg verification for a vector of `AvailablePayloads`. This is more efficient than
    /// calling `verify_kzg_for_available_block` in a loop.
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    #[instrument(skip_all)]
    pub fn batch_verify_kzg_for_available_payloads(
        &self,
        available_payloads: &Vec<AvailablePayload<T::EthSpec>>,
    ) -> Result<(), AvailabilityCheckError> {
        let all_data_columns = available_payloads
            .iter()
            .filter(|available_payload| {
                self.custody_context
                    .data_columns_required_for_payload(&available_payload.payload)
            })
            // this clone is cheap as it's cloning an Arc
            .filter_map(|available_payload| available_payload.column_data.data_columns())
            .flatten()
            .collect::<Vec<_>>();

        for available_payload in available_payloads {
            let payload_data_required = self
                .custody_context
                .data_columns_required_for_payload(&available_payload.payload);
            if let AvailablePayloadData::NoData = available_payload.data()
                && payload_data_required
            {
                return Err(AvailabilityCheckError::MissingCustodyColumns);
            }
        }

        // verify kzg for all data columns at once
        if !all_data_columns.is_empty() {
            // Attributes fault to the specific peer that sent an invalid column
            verify_kzg_for_data_column_list(all_data_columns.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;
        }

        Ok(())
    }

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            payload_cache_size: self.availability_cache.payload_cache_size(),
        }
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub payload_cache_size: usize,
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
        debug!("Gloas fork not configured, not starting availability cache maintenance service");
    }
    // TODO(gloas)
    // this cache only needs to be maintained if deneb is configured
    // if chain.spec.deneb_fork_epoch.is_some() {
    //     let overflow_cache = chain.data_availability_checker.availability_cache.clone();
    //     executor.spawn(
    //         async move { availability_cache_maintenance_service(chain, overflow_cache).await },
    //         "availability_cache_service",
    //     );
    // } else {
    //     debug!("Deneb fork not configured, not starting availability cache maintenance service");
    // }
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
                    // Shutdown service if deneb fork epoch not set. Unreachable as the same check is performed above.
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

#[derive(Debug, Clone)]
// TODO(gloas) Move this to `payload_verification_types.rs`
pub enum AvailablePayloadData<E: EthSpec> {
    /// Payload has zero blobs
    NoData,
    /// Payload has more than zero blobs
    DataColumns(DataColumnSidecarList<E>),
}

impl<E: EthSpec> AvailablePayloadData<E> {
    pub fn new_with_data_columns(columns: DataColumnSidecarList<E>) -> Self {
        if columns.is_empty() {
            Self::NoData
        } else {
            Self::DataColumns(columns)
        }
    }

    pub fn data_columns(&self) -> Option<DataColumnSidecarList<E>> {
        match self {
            AvailablePayloadData::NoData => None,
            AvailablePayloadData::DataColumns(data_columns) => Some(data_columns.clone()),
        }
    }

    pub fn data_columns_len(&self) -> usize {
        if let Some(data_columns) = self.data_columns() {
            data_columns.len()
        } else {
            0
        }
    }
}

/// A fully available payload that is ready to be imported into fork choice.
#[derive(Debug, Clone, Educe)]
#[educe(Hash(bound(E: EthSpec)))]
pub struct AvailablePayload<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    payload: Arc<SignedExecutionPayloadEnvelope<E>>,
    #[educe(Hash(ignore))]
    column_data: AvailablePayloadData<E>,
    #[educe(Hash(ignore))]
    /// Timestamp at which this payload first became available (UNIX timestamp, time since 1970).
    payload_available_timestamp: Option<Duration>,
    #[educe(Hash(ignore))]
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> AvailablePayload<E> {
    /// Constructs an `AvailablePayload` from a payload and optional data.
    /// - If `column_data` is `DataColumns`, constructs `AvailablePayload` variant after column validation.
    /// - If `column_data` is `NoData`, constructs `AvailablePayload` after verifying that the payload is not expecting columns.
    ///   Returns `AvailabilityCheckError` if:
    /// - `column_data` contains data not required by the block
    /// - Required `column_data` is missing
    pub fn new<T>(
        payload: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        block: Arc<SignedBeaconBlock<E>>,
        column_data: AvailablePayloadData<T::EthSpec>,
        da_checker: &DataAvailabilityChecker<T>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        // Ensure payload availability
        let columns_required = da_checker
            .custody_context()
            .data_columns_required_for_payload(&payload);

        match &column_data {
            AvailablePayloadData::NoData => {
                if columns_required {
                    return Err(AvailabilityCheckError::MissingCustodyColumns);
                }
            }
            AvailablePayloadData::DataColumns(data_columns) => {
                if !columns_required {
                    // TODO(gloas) potential refactor here
                    return Err(AvailabilityCheckError::MissingCustodyColumns);
                }

                let mut column_indices = da_checker
                    .custody_context
                    .custody_columns_for_epoch(
                        Some(payload.message.slot.epoch(T::EthSpec::slots_per_epoch())),
                        &spec,
                    )
                    .iter()
                    .collect::<HashSet<_>>();

                for data_column in data_columns {
                    column_indices.remove(&data_column.index());
                }

                if !column_indices.is_empty() {
                    return Err(AvailabilityCheckError::MissingCustodyColumns);
                }
            }
        }

        Ok(Self {
            block_root: payload.message.beacon_block_root,
            block,
            payload,
            column_data,
            payload_available_timestamp: None,
            spec: spec.clone(),
        })
    }

    pub fn payload(&self) -> &SignedExecutionPayloadEnvelope<E> {
        &self.payload
    }
    pub fn payload_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        self.payload.clone()
    }

    pub fn payload_available_timestamp(&self) -> Option<Duration> {
        self.payload_available_timestamp
    }

    pub fn data(&self) -> &AvailablePayloadData<E> {
        &self.column_data
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(
        self,
    ) -> (
        Hash256,
        Arc<SignedExecutionPayloadEnvelope<E>>,
        AvailablePayloadData<E>,
    ) {
        let AvailablePayload {
            block_root,
            payload,
            column_data,
            ..
        } = self;
        (block_root, payload, column_data)
    }

    /// Only used for testing
    pub fn __clone_without_recv(&self) -> Self {
        Self {
            block_root: self.block_root,
            payload: self.payload.clone(),
            block: self.block.clone(),
            column_data: match &self.column_data {
                AvailablePayloadData::NoData => AvailablePayloadData::NoData,
                AvailablePayloadData::DataColumns(data_columns) => {
                    AvailablePayloadData::DataColumns(data_columns.clone())
                }
            },
            payload_available_timestamp: self.payload_available_timestamp,
            spec: self.spec.clone(),
        }
    }
}

#[derive(Debug)]
pub enum MaybeAvailablePayload<E: EthSpec> {
    /// This payload is fully available.
    Available(AvailablePayload<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending {
        block_root: Hash256,
        payload: Arc<SignedExecutionPayloadEnvelope<E>>,
    },
}

impl<E: EthSpec> MaybeAvailablePayload<E> {
    pub fn block_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        match self {
            Self::Available(payload) => payload.payload_cloned(),
            Self::AvailabilityPending { payload, .. } => payload.clone(),
        }
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::CustodyContext;
//     use crate::block_verification_types::RpcBlock;
//     use crate::custody_context::NodeCustodyType;
//     use crate::data_column_verification::CustodyDataColumn;
//     use crate::test_utils::{
//         EphemeralHarnessType, NumBlobs, generate_data_column_indices_rand_order,
//         generate_rand_block_and_data_columns, get_kzg,
//     };
//     use rand::SeedableRng;
//     use rand::prelude::StdRng;
//     use slot_clock::{SlotClock, TestingSlotClock};
//     use std::collections::HashSet;
//     use std::sync::Arc;
//     use std::time::Duration;
//     use store::HotColdDB;
//     use types::data::DataColumn;
//     use types::{ChainSpec, ColumnIndex, EthSpec, ForkName, MainnetEthSpec, Slot};

//     type E = MainnetEthSpec;
//     type T = EphemeralHarnessType<E>;

//     /// Test to verify any extra RPC columns received that are not part of the "effective" CGC for
//     /// the slot are excluded from import.
//     #[test]
//     fn should_exclude_rpc_columns_not_required_for_sampling() {
//         // SETUP
//         let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);

//         let da_checker = new_da_checker(spec.clone());
//         let custody_context = &da_checker.custody_context;

//         // GIVEN a single 32 ETH validator is attached slot 0
//         let epoch = Epoch::new(0);
//         let validator_0 = 0;
//         custody_context.register_validators(
//             vec![(validator_0, 32_000_000_000)],
//             epoch.start_slot(E::slots_per_epoch()),
//             &spec,
//         );
//         assert_eq!(
//             custody_context.num_of_data_columns_to_sample(epoch, &spec),
//             spec.validator_custody_requirement as usize,
//             "sampling size should be the minimal custody requirement == 8"
//         );

//         // WHEN additional attached validators result in a CGC increase to 10 at the end slot of the same epoch
//         let validator_1 = 1;
//         let cgc_change_slot = epoch.end_slot(E::slots_per_epoch());
//         custody_context.register_validators(
//             vec![(validator_1, 32_000_000_000 * 9)],
//             cgc_change_slot,
//             &spec,
//         );
//         // AND custody columns (8) and any new extra columns (2) are received via RPC responses.
//         // NOTE: block lookup uses the **latest** CGC (10) instead of the effective CGC (8) as the slot is unknown.
//         let (_, data_columns) = generate_rand_block_and_data_columns::<E>(
//             ForkName::Fulu,
//             NumBlobs::Number(1),
//             &mut rng,
//             &spec,
//         );
//         let block_root = Hash256::random();
//         let custody_columns = custody_context.custody_columns_for_epoch(None, &spec);
//         let requested_columns = &custody_columns[..10];
//         da_checker
//             .put_rpc_custody_columns(
//                 block_root,
//                 cgc_change_slot,
//                 data_columns
//                     .into_iter()
//                     .filter(|d| requested_columns.contains(&d.index))
//                     .collect(),
//             )
//             .expect("should put rpc custody columns");

//         // THEN the sampling size for the end slot of the same epoch remains unchanged
//         let sampling_columns = custody_context.sampling_columns_for_epoch(epoch, &spec);
//         assert_eq!(
//             sampling_columns.len(),
//             spec.validator_custody_requirement as usize // 8
//         );
//         // AND any extra columns received via RPC responses are excluded from import.
//         let actual_cached: HashSet<ColumnIndex> = da_checker
//             .cached_data_column_indexes(&block_root)
//             .expect("should have cached data columns")
//             .into_iter()
//             .collect();
//         let expected_sampling_columns = sampling_columns.iter().copied().collect::<HashSet<_>>();
//         assert_eq!(
//             actual_cached, expected_sampling_columns,
//             "should cache only the effective sampling columns"
//         );
//         assert!(
//             actual_cached.len() < requested_columns.len(),
//             "extra columns should be excluded"
//         )
//     }

//     /// Test to verify any extra gossip columns received that are not part of the "effective" CGC for
//     /// the slot are excluded from import.
//     #[test]
//     fn should_exclude_gossip_columns_not_required_for_sampling() {
//         // SETUP
//         let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);

//         let da_checker = new_da_checker(spec.clone());
//         let custody_context = &da_checker.custody_context;

//         // GIVEN a single 32 ETH validator is attached slot 0
//         let epoch = Epoch::new(0);
//         let validator_0 = 0;
//         custody_context.register_validators(
//             vec![(validator_0, 32_000_000_000)],
//             epoch.start_slot(E::slots_per_epoch()),
//             &spec,
//         );
//         assert_eq!(
//             custody_context.num_of_data_columns_to_sample(epoch, &spec),
//             spec.validator_custody_requirement as usize,
//             "sampling size should be the minimal custody requirement == 8"
//         );

//         // WHEN additional attached validators result in a CGC increase to 10 at the end slot of the same epoch
//         let validator_1 = 1;
//         let cgc_change_slot = epoch.end_slot(E::slots_per_epoch());
//         custody_context.register_validators(
//             vec![(validator_1, 32_000_000_000 * 9)],
//             cgc_change_slot,
//             &spec,
//         );
//         // AND custody columns (8) and any new extra columns (2) are received via gossip.
//         // NOTE: CGC updates results in new topics subscriptions immediately, and extra columns may start to
//         // arrive via gossip.
//         let (_, data_columns) = generate_rand_block_and_data_columns::<E>(
//             ForkName::Fulu,
//             NumBlobs::Number(1),
//             &mut rng,
//             &spec,
//         );
//         let block_root = Hash256::random();
//         let custody_columns = custody_context.custody_columns_for_epoch(None, &spec);
//         let requested_columns = &custody_columns[..10];
//         let gossip_columns = data_columns
//             .into_iter()
//             .filter(|d| requested_columns.contains(&d.index))
//             .map(GossipVerifiedDataColumn::<T>::__new_for_testing)
//             .collect::<Vec<_>>();
//         da_checker
//             .put_gossip_verified_data_columns(block_root, cgc_change_slot, gossip_columns)
//             .expect("should put gossip custody columns");

//         // THEN the sampling size for the end slot of the same epoch remains unchanged
//         let sampling_columns = custody_context.sampling_columns_for_epoch(epoch, &spec);
//         assert_eq!(
//             sampling_columns.len(),
//             spec.validator_custody_requirement as usize // 8
//         );
//         // AND any extra columns received via gossip responses are excluded from import.
//         let actual_cached: HashSet<ColumnIndex> = da_checker
//             .cached_data_column_indexes(&block_root)
//             .expect("should have cached data columns")
//             .into_iter()
//             .collect();
//         let expected_sampling_columns = sampling_columns.iter().copied().collect::<HashSet<_>>();
//         assert_eq!(
//             actual_cached, expected_sampling_columns,
//             "should cache only the effective sampling columns"
//         );
//         assert!(
//             actual_cached.len() < requested_columns.len(),
//             "extra columns should be excluded"
//         )
//     }

//     /// Regression test for KZG verification truncation bug (https://github.com/sigp/lighthouse/pull/7927)
//     #[test]
//     fn verify_kzg_for_rpc_blocks_should_not_truncate_data_columns() {
//         let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
//         let da_checker = new_da_checker(spec.clone());

//         // GIVEN multiple RPC blocks with data columns totalling more than 128
//         let blocks_with_columns = (0..2)
//             .map(|index| {
//                 let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
//                     ForkName::Fulu,
//                     NumBlobs::Number(1),
//                     &mut rng,
//                     &spec,
//                 );

//                 let custody_columns = if index == 0 {
//                     // 128 valid data columns in the first block
//                     data_columns
//                 } else {
//                     // invalid data columns in the second block
//                     data_columns
//                         .into_iter()
//                         .map(|d| {
//                             let invalid_sidecar = DataColumnSidecar {
//                                 column: DataColumn::<E>::empty(),
//                                 ..d.as_ref().clone()
//                             };
//                             CustodyDataColumn::from_asserted_custody(Arc::new(invalid_sidecar))
//                                 .as_data_column()
//                                 .clone()
//                         })
//                         .collect::<Vec<_>>()
//                 };

//                 let block_data = AvailableBlockData::new_with_data_columns(custody_columns);
//                 let da_checker = Arc::new(new_da_checker(spec.clone()));
//                 RpcBlock::new(Arc::new(block), Some(block_data), &da_checker, spec.clone())
//                     .expect("should create RPC block with custody columns")
//             })
//             .collect::<Vec<_>>();

//         let available_blocks = blocks_with_columns
//             .iter()
//             .filter_map(|block| match block {
//                 RpcBlock::FullyAvailable(available_block) => Some(available_block.clone()),
//                 RpcBlock::BlockOnly { .. } => None,
//             })
//             .collect::<Vec<_>>();

//         // WHEN verifying all blocks together (totalling 256 data columns)
//         let verification_result =
//             da_checker.batch_verify_kzg_for_available_blocks(&available_blocks);

//         // THEN batch block verification should fail due to 128 invalid columns in the second block
//         verification_result.expect_err("should have failed to verify blocks");
//     }

//     #[test]
//     fn should_exclude_reconstructed_columns_not_required_for_sampling() {
//         // SETUP
//         let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);

//         let da_checker = new_da_checker(spec.clone());
//         let custody_context = &da_checker.custody_context;

//         // Set custody requirement to 65 columns (enough to trigger reconstruction)
//         let epoch = Epoch::new(1);
//         custody_context.register_validators(
//             vec![(0, 2_048_000_000_000), (1, 32_000_000_000)], // 64 + 1
//             Slot::new(0),
//             &spec,
//         );
//         let sampling_requirement = custody_context.num_of_data_columns_to_sample(epoch, &spec);
//         assert_eq!(
//             sampling_requirement, 65,
//             "sampling requirement should be 65"
//         );

//         let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
//             ForkName::Fulu,
//             NumBlobs::Number(1),
//             &mut rng,
//             &spec,
//         );
//         let block_root = Hash256::random();
//         // Add the block to the DA checker
//         da_checker
//             .availability_cache
//             .put_pre_execution_block(block_root, Arc::new(block), BlockImportSource::Gossip)
//             .expect("should put block");

//         // Add 64 columns to the da checker (enough to be able to reconstruct)
//         // Order by all_column_indices_ordered, then take first 64
//         let custody_columns = custody_context.custody_columns_for_epoch(None, &spec);
//         let custody_columns = custody_columns
//             .iter()
//             .filter_map(|&col_idx| data_columns.iter().find(|d| d.index == col_idx).cloned())
//             .take(64)
//             .map(|d| {
//                 KzgVerifiedCustodyDataColumn::from_asserted_custody(
//                     KzgVerifiedDataColumn::__new_for_testing(d),
//                 )
//             })
//             .collect::<Vec<_>>();

//         da_checker
//             .availability_cache
//             .put_kzg_verified_data_columns(block_root, custody_columns)
//             .expect("should put custody columns");

//         // Try reconstrucing
//         let reconstruction_result = da_checker
//             .reconstruct_data_columns(&block_root)
//             .expect("should reconstruct columns");

//         // Reconstruction should succeed
//         let (_availability, reconstructed_columns) = match reconstruction_result {
//             DataColumnReconstructionResult::Success(result) => result,
//             e => {
//                 panic!("Expected successful reconstruction {:?}", e);
//             }
//         };

//         // Remaining 64 columns should be reconstructed
//         assert_eq!(
//             reconstructed_columns.len(),
//             sampling_requirement - spec.number_of_custody_groups as usize / 2,
//             "should reconstruct the remaining 1 columns"
//         );

//         // Only the columns required for custody (65) should be imported into the cache
//         let sampling_columns = custody_context.sampling_columns_for_epoch(epoch, &spec);
//         let actual_cached: HashSet<ColumnIndex> = da_checker
//             .cached_data_column_indexes(&block_root)
//             .expect("should have cached data columns")
//             .into_iter()
//             .collect();
//         let expected_sampling_columns = sampling_columns.iter().copied().collect::<HashSet<_>>();
//         assert_eq!(
//             actual_cached, expected_sampling_columns,
//             "should cache only the required custody columns, not all reconstructed columns"
//         );
//     }

//     fn new_da_checker(spec: Arc<ChainSpec>) -> DataAvailabilityChecker<T> {
//         let slot_clock = TestingSlotClock::new(
//             Slot::new(0),
//             Duration::from_secs(0),
//             Duration::from_secs(spec.seconds_per_slot),
//         );
//         let kzg = get_kzg(&spec);
//         let store = Arc::new(HotColdDB::open_ephemeral(<_>::default(), spec.clone()).unwrap());
//         let ordered_custody_column_indices = generate_data_column_indices_rand_order::<E>();
//         let custody_context = Arc::new(CustodyContext::new(
//             NodeCustodyType::Fullnode,
//             ordered_custody_column_indices,
//             &spec,
//         ));
//         let complete_blob_backfill = false;
//         DataAvailabilityChecker::new(
//             complete_blob_backfill,
//             slot_clock,
//             kzg,
//             store,
//             custody_context,
//             spec,
//         )
//         .expect("should initialise data availability checker")
//     }
// }
