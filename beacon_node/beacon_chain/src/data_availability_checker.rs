use crate::blob_verification::{verify_kzg_for_blob_list, GossipVerifiedBlob, KzgVerifiedBlobList};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
use crate::data_availability_checker::overflow_lru_cache::{
    DataAvailabilityCheckerInner, ReconstructColumnsDecision,
};
use crate::{metrics, BeaconChain, BeaconChainTypes, BeaconStore};
use kzg::Kzg;
use slog::{debug, error, Logger};
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::{
    BlobSidecarList, ChainSpec, DataColumnIdentifier, DataColumnSidecar, DataColumnSidecarList,
    Epoch, EthSpec, Hash256, RuntimeVariableList, SignedBeaconBlock,
};

mod error;
mod overflow_lru_cache;
mod state_lru_cache;

use crate::data_column_verification::{
    verify_kzg_for_data_column, verify_kzg_for_data_column_list, CustodyDataColumn,
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
pub use error::{Error as AvailabilityCheckError, ErrorCategory as AvailabilityCheckErrorCategory};
use types::non_zero_usize::new_non_zero_usize;

/// The LRU Cache stores `PendingComponents` which can store up to
/// `MAX_BLOBS_PER_BLOCK = 6` blobs each. A `BlobSidecar` is 0.131256 MB. So
/// the maximum size of a `PendingComponents` is ~ 0.787536 MB. Setting this
/// to 1024 means the maximum size of the cache is ~ 0.8 GB. But the cache
/// will target a size of less than 75% of capacity.
pub const OVERFLOW_LRU_CAPACITY: NonZeroUsize = new_non_zero_usize(1024);
/// Until tree-states is implemented, we can't store very many states in memory :(
pub const STATE_LRU_CAPACITY_NON_ZERO: NonZeroUsize = new_non_zero_usize(2);
pub const STATE_LRU_CAPACITY: usize = STATE_LRU_CAPACITY_NON_ZERO.get();

/// Cache to hold fully valid data that can't be imported to fork-choice yet. After Dencun hard-fork
/// blocks have a sidecar of data that is received separately from the network. We call the concept
/// of a block "becoming available" when all of its import dependencies are inserted into this
/// cache.
///
/// Usually a block becomes available on its slot within a second of receiving its first component
/// over gossip. However, a block may never become available if a malicious proposer does not
/// publish its data, or there are network issues that prevent us from receiving it. If the block
/// does not become available after some time we can safely forget about it. Consider these two
/// cases:
///
/// - Global unavailability: If nobody has received the block components it's likely that the
///   proposer never made the block available. So we can safely forget about the block as it will
///   never become available.
/// - Local unavailability: Some fraction of the network has received all block components, but not us.
///   Some of our peers will eventually attest to a descendant of that block and lookup sync will
///   fetch its components. Therefore it's not strictly necessary to hold to the partially available
///   block for too long as we can recover from other peers.
///
/// Even in periods of non-finality, the proposer is expected to publish the block's data
/// immediately. Because this cache only holds fully valid data, its capacity is bound to 1 block
/// per slot and fork: before inserting into this cache we check the proposer signature and correct
/// proposer. Having a capacity > 1 is an optimization to prevent sync lookup from having re-fetch
/// data during moments of unstable network conditions.
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    availability_cache: Arc<DataAvailabilityCheckerInner<T>>,
    slot_clock: T::SlotClock,
    kzg: Arc<Kzg>,
    spec: Arc<ChainSpec>,
    log: Logger,
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);

#[derive(Debug)]
pub enum DataColumnReconstructionResult<E: EthSpec> {
    Success(AvailabilityAndReconstructedColumns<E>),
    NotStarted(&'static str),
    RecoveredColumnsNotImported(&'static str),
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
#[derive(PartialEq)]
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedBlock<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(block) => write!(f, "Available({:?})", block.import_data.block_root),
        }
    }
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        slot_clock: T::SlotClock,
        kzg: Arc<Kzg>,
        store: BeaconStore<T>,
        import_all_data_columns: bool,
        spec: Arc<ChainSpec>,
        log: Logger,
    ) -> Result<Self, AvailabilityCheckError> {
        let custody_subnet_count = if import_all_data_columns {
            spec.data_column_sidecar_subnet_count as usize
        } else {
            spec.custody_requirement as usize
        };

        let subnet_sampling_size =
            std::cmp::max(custody_subnet_count, spec.samples_per_slot as usize);
        let sampling_column_count =
            subnet_sampling_size.saturating_mul(spec.data_columns_per_subnet());

        let inner = DataAvailabilityCheckerInner::new(
            OVERFLOW_LRU_CAPACITY,
            store,
            sampling_column_count,
            spec.clone(),
        )?;
        Ok(Self {
            availability_cache: Arc::new(inner),
            slot_clock,
            kzg,
            spec,
            log,
        })
    }

    pub fn get_sampling_column_count(&self) -> usize {
        self.availability_cache.sampling_column_count()
    }

    pub(crate) fn is_supernode(&self) -> bool {
        self.get_sampling_column_count() == self.spec.number_of_columns
    }

    /// Checks if the block root is currenlty in the availability cache awaiting import because
    /// of missing components.
    pub fn get_execution_valid_block(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedBeaconBlock<T::EthSpec>>> {
        self.availability_cache
            .get_execution_valid_block(block_root)
    }

    /// Return the set of cached blob indexes for `block_root`. Returns None if there is no block
    /// component for `block_root`.
    pub fn cached_blob_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        self.availability_cache
            .peek_pending_components(block_root, |components| {
                components.map(|components| {
                    components
                        .get_cached_blobs()
                        .iter()
                        .filter_map(|blob| blob.as_ref().map(|blob| blob.blob_index()))
                        .collect::<Vec<_>>()
                })
            })
    }

    /// Return the set of cached custody column indexes for `block_root`. Returns None if there is
    /// no block component for `block_root`.
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        self.availability_cache
            .peek_pending_components(block_root, |components| {
                components.map(|components| components.get_cached_data_columns_indices())
            })
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_blob(blob_id)
    }

    /// Get a data column from the availability cache.
    pub fn get_data_column(
        &self,
        data_column_id: &DataColumnIdentifier,
    ) -> Result<Option<Arc<DataColumnSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_data_column(data_column_id)
    }

    /// Put a list of blobs received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let seen_timestamp = self
            .slot_clock
            .now_duration()
            .ok_or(AvailabilityCheckError::SlotClockError)?;

        // Note: currently not reporting which specific blob is invalid because we fetch all blobs
        // from the same peer for both lookup and range sync.

        let verified_blobs =
            KzgVerifiedBlobList::new(blobs.iter().flatten().cloned(), &self.kzg, seen_timestamp)
                .map_err(AvailabilityCheckError::InvalidBlobs)?;

        self.availability_cache
            .put_kzg_verified_blobs(block_root, verified_blobs, &self.log)
    }

    /// Put a list of custody columns received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    #[allow(clippy::type_complexity)]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // TODO(das): report which column is invalid for proper peer scoring
        // TODO(das): batch KZG verification here, but fallback into checking each column
        // individually to report which column(s) are invalid.
        let verified_custody_columns = custody_columns
            .into_iter()
            .map(|column| {
                let index = column.index;
                Ok(KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::new(column, &self.kzg)
                        .map_err(|e| AvailabilityCheckError::InvalidColumn(index, e))?,
                ))
            })
            .collect::<Result<Vec<_>, AvailabilityCheckError>>()?;

        self.availability_cache.put_kzg_verified_data_columns(
            block_root,
            verified_custody_columns,
            &self.log,
        )
    }

    /// Put a list of blobs received from the EL pool into the availability cache.
    ///
    /// This DOES NOT perform KZG verification because the KZG proofs should have been constructed
    /// immediately prior to calling this function so they are assumed to be valid.
    pub fn put_engine_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let seen_timestamp = self
            .slot_clock
            .now_duration()
            .ok_or(AvailabilityCheckError::SlotClockError)?;

        let verified_blobs =
            KzgVerifiedBlobList::from_verified(blobs.iter().flatten().cloned(), seen_timestamp);

        self.availability_cache
            .put_kzg_verified_blobs(block_root, verified_blobs, &self.log)
    }

    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_blob(
        &self,
        gossip_blob: GossipVerifiedBlob<T>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache.put_kzg_verified_blobs(
            gossip_blob.block_root(),
            vec![gossip_blob.into_inner()],
            &self.log,
        )
    }

    /// Check if we've cached other data columns for this block. If it satisfies the custody requirement and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the data column sidecar.
    ///
    /// This should only accept gossip verified data columns, so we should not have to worry about dupes.
    #[allow(clippy::type_complexity)]
    pub fn put_gossip_data_columns(
        &self,
        block_root: Hash256,
        gossip_data_columns: Vec<GossipVerifiedDataColumn<T>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let custody_columns = gossip_data_columns
            .into_iter()
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.availability_cache.put_kzg_verified_data_columns(
            block_root,
            custody_columns,
            &self.log,
        )
    }

    /// Check if we have all the blobs for a block. Returns `Availability` which has information
    /// about whether all components have been received or more are required.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_pending_executed_block(executed_block, &self.log)
    }

    pub fn remove_pending_components(&self, block_root: Hash256) {
        self.availability_cache
            .remove_pending_components(block_root)
    }

    /// Verifies kzg commitments for an RpcBlock, returns a `MaybeAvailableBlock` that may
    /// include the fully available block.
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_block(
        &self,
        block: RpcBlock<T::EthSpec>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        let (block_root, block, blobs, data_columns) = block.deconstruct();
        if self.blobs_required_for_block(&block) {
            return if let Some(blob_list) = blobs.as_ref() {
                verify_kzg_for_blob_list(blob_list.iter(), &self.kzg)
                    .map_err(AvailabilityCheckError::InvalidBlobs)?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blobs,
                    blobs_available_timestamp: None,
                    data_columns: None,
                    spec: self.spec.clone(),
                }))
            } else {
                Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
            };
        }
        if self.data_columns_required_for_block(&block) {
            return if let Some(data_column_list) = data_columns.as_ref() {
                verify_kzg_for_data_column_list_with_scoring(
                    data_column_list
                        .iter()
                        .map(|custody_column| custody_column.as_data_column()),
                    &self.kzg,
                )?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blobs: None,
                    blobs_available_timestamp: None,
                    data_columns: Some(
                        data_column_list
                            .into_iter()
                            .map(|d| d.clone_arc())
                            .collect(),
                    ),
                    spec: self.spec.clone(),
                }))
            } else {
                Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
            };
        }

        Ok(MaybeAvailableBlock::Available(AvailableBlock {
            block_root,
            block,
            blobs: None,
            blobs_available_timestamp: None,
            data_columns: None,
            spec: self.spec.clone(),
        }))
    }

    /// Checks if a vector of blocks are available. Returns a vector of `MaybeAvailableBlock`
    /// This is more efficient than calling `verify_kzg_for_rpc_block` in a loop as it does
    /// all kzg verification at once
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_blocks(
        &self,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<Vec<MaybeAvailableBlock<T::EthSpec>>, AvailabilityCheckError> {
        let mut results = Vec::with_capacity(blocks.len());
        let all_blobs: BlobSidecarList<T::EthSpec> = blocks
            .iter()
            .filter(|block| self.blobs_required_for_block(block.as_block()))
            // this clone is cheap as it's cloning an Arc
            .filter_map(|block| block.blobs().cloned())
            .flatten()
            .collect::<Vec<_>>()
            .into();

        // verify kzg for all blobs at once
        if !all_blobs.is_empty() {
            verify_kzg_for_blob_list(all_blobs.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidBlobs)?;
        }

        let all_data_columns = blocks
            .iter()
            .filter(|block| self.data_columns_required_for_block(block.as_block()))
            // this clone is cheap as it's cloning an Arc
            .filter_map(|block| block.custody_columns().cloned())
            .flatten()
            .map(CustodyDataColumn::into_inner)
            .collect::<Vec<_>>();
        let all_data_columns =
            RuntimeVariableList::from_vec(all_data_columns, self.spec.number_of_columns);

        // verify kzg for all data columns at once
        if !all_data_columns.is_empty() {
            // TODO: Need to also attribute which specific block is faulty
            verify_kzg_for_data_column_list_with_scoring(all_data_columns.iter(), &self.kzg)?;
        }

        for block in blocks {
            let (block_root, block, blobs, data_columns) = block.deconstruct();

            let maybe_available_block = if self.blobs_required_for_block(&block) {
                if blobs.is_some() {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs,
                        blobs_available_timestamp: None,
                        data_columns: None,
                        spec: self.spec.clone(),
                    })
                } else {
                    MaybeAvailableBlock::AvailabilityPending { block_root, block }
                }
            } else if self.data_columns_required_for_block(&block) {
                if data_columns.is_some() {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs: None,
                        data_columns: data_columns.map(|data_columns| {
                            data_columns.into_iter().map(|d| d.into_inner()).collect()
                        }),
                        blobs_available_timestamp: None,
                        spec: self.spec.clone(),
                    })
                } else {
                    MaybeAvailableBlock::AvailabilityPending { block_root, block }
                }
            } else {
                MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blobs: None,
                    data_columns: None,
                    blobs_available_timestamp: None,
                    spec: self.spec.clone(),
                })
            };

            results.push(maybe_available_block);
        }

        Ok(results)
    }

    /// Determines the blob requirements for a block. If the block is pre-deneb, no blobs are required.
    /// If the epoch is from prior to the data availability boundary, no blobs are required.
    pub fn blobs_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.da_check_required_for_epoch(epoch) && !self.spec.is_peer_das_enabled_for_epoch(epoch)
    }

    /// Determines the data column requirements for an epoch.
    /// - If the epoch is pre-peerdas, no data columns are required.
    /// - If the epoch is from prior to the data availability boundary, no data columns are required.
    pub fn data_columns_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.da_check_required_for_epoch(epoch) && self.spec.is_peer_das_enabled_for_epoch(epoch)
    }

    /// See `Self::blobs_required_for_epoch`
    fn blobs_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.blobs_required_for_epoch(block.epoch())
    }

    /// See `Self::data_columns_required_for_epoch`
    fn data_columns_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.data_columns_required_for_epoch(block.epoch())
    }

    /// The epoch at which we require a data availability check in block processing.
    /// `None` if the `Deneb` fork is disabled.
    pub fn data_availability_boundary(&self) -> Option<Epoch> {
        let fork_epoch = self.spec.deneb_fork_epoch?;
        let current_slot = self.slot_clock.now()?;
        Some(std::cmp::max(
            fork_epoch,
            current_slot
                .epoch(T::EthSpec::slots_per_epoch())
                .saturating_sub(self.spec.min_epochs_for_blob_sidecars_requests),
        ))
    }

    /// Returns true if the given epoch lies within the da boundary and false otherwise.
    pub fn da_check_required_for_epoch(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .map_or(false, |da_epoch| block_epoch >= da_epoch)
    }

    /// Returns `true` if the current epoch is greater than or equal to the `Deneb` epoch.
    pub fn is_deneb(&self) -> bool {
        self.slot_clock.now().map_or(false, |slot| {
            self.spec.deneb_fork_epoch.map_or(false, |deneb_epoch| {
                let now_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
                now_epoch >= deneb_epoch
            })
        })
    }

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            state_cache_size: self.availability_cache.state_cache_size(),
            block_cache_size: self.availability_cache.block_cache_size(),
        }
    }

    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        let pending_components = match self
            .availability_cache
            .check_and_set_reconstruction_started(block_root)
        {
            ReconstructColumnsDecision::Yes(pending_components) => pending_components,
            ReconstructColumnsDecision::No(reason) => {
                return Ok(DataColumnReconstructionResult::NotStarted(reason));
            }
        };

        metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS);
        let timer = metrics::start_timer(&metrics::DATA_AVAILABILITY_RECONSTRUCTION_TIME);

        let all_data_columns = KzgVerifiedCustodyDataColumn::reconstruct_columns(
            &self.kzg,
            &pending_components.verified_data_columns,
            &self.spec,
        )
        .map_err(|e| {
            error!(
                self.log,
                "Error reconstructing data columns";
                "block_root" => ?block_root,
                "error" => ?e
            );
            self.availability_cache
                .handle_reconstruction_failure(block_root);
            metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES);
            AvailabilityCheckError::ReconstructColumnsError(e)
        })?;

        // Check indices from cache again to make sure we don't publish components we've already received.
        let Some(existing_column_indices) = self.cached_data_column_indexes(block_root) else {
            return Ok(DataColumnReconstructionResult::RecoveredColumnsNotImported(
                "block already imported",
            ));
        };

        let data_columns_to_publish = all_data_columns
            .into_iter()
            .filter(|d| !existing_column_indices.contains(&d.index()))
            .collect::<Vec<_>>();

        let Some(slot) = data_columns_to_publish
            .first()
            .map(|d| d.as_data_column().slot())
        else {
            return Ok(DataColumnReconstructionResult::RecoveredColumnsNotImported(
                "No new columns to import and publish",
            ));
        };

        metrics::stop_timer(timer);
        metrics::inc_counter_by(
            &metrics::DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS,
            data_columns_to_publish.len() as u64,
        );

        debug!(self.log, "Reconstructed columns";
            "count" => data_columns_to_publish.len(),
            "block_root" => ?block_root,
            "slot" => slot,
        );

        self.availability_cache
            .put_kzg_verified_data_columns(*block_root, data_columns_to_publish.clone(), &self.log)
            .map(|availability| {
                DataColumnReconstructionResult::Success((
                    availability,
                    data_columns_to_publish
                        .into_iter()
                        .map(|d| d.clone_arc())
                        .collect::<Vec<_>>(),
                ))
            })
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub state_cache_size: usize,
    pub block_cache_size: usize,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // this cache only needs to be maintained if deneb is configured
    if chain.spec.deneb_fork_epoch.is_some() {
        let overflow_cache = chain.data_availability_checker.availability_cache.clone();
        executor.spawn(
            async move { availability_cache_maintenance_service(chain, overflow_cache).await },
            "availability_cache_service",
        );
    } else {
        debug!(
            chain.log,
            "Deneb fork not configured, not starting availability cache maintenance service"
        );
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

                let Some(deneb_fork_epoch) = chain.spec.deneb_fork_epoch else {
                    // shutdown service if deneb fork epoch not set
                    break;
                };

                debug!(
                    chain.log,
                    "Availability cache maintenance service firing";
                );
                let Some(current_epoch) = chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                else {
                    continue;
                };

                if current_epoch < deneb_fork_epoch {
                    // we are not in deneb yet
                    continue;
                }

                let finalized_epoch = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .finalized_checkpoint()
                    .epoch;
                // any data belonging to an epoch before this should be pruned
                let cutoff_epoch = std::cmp::max(
                    finalized_epoch + 1,
                    std::cmp::max(
                        current_epoch
                            .saturating_sub(chain.spec.min_epochs_for_blob_sidecars_requests),
                        deneb_fork_epoch,
                    ),
                );

                if let Err(e) = overflow_cache.do_maintenance(cutoff_epoch) {
                    error!(chain.log, "Failed to maintain availability cache"; "error" => ?e);
                }
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                tokio::time::sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
}

fn verify_kzg_for_data_column_list_with_scoring<'a, E: EthSpec, I>(
    data_column_iter: I,
    kzg: &'a Kzg,
) -> Result<(), AvailabilityCheckError>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    let Err(batch_err) = verify_kzg_for_data_column_list(data_column_iter.clone(), kzg) else {
        return Ok(());
    };

    let data_columns = data_column_iter.collect::<Vec<_>>();
    // Find which column is invalid. If len is 1 or 0 continue to default case below.
    // If len > 1 at least one column MUST fail.
    if data_columns.len() > 1 {
        for data_column in data_columns {
            if let Err(e) = verify_kzg_for_data_column(data_column.clone(), kzg) {
                return Err(AvailabilityCheckError::InvalidColumn(data_column.index, e));
            }
        }
    }

    // len 0 should never happen
    Err(AvailabilityCheckError::InvalidColumn(0, batch_err))
}

/// A fully available block that is ready to be imported into fork choice.
#[derive(Clone, Debug, PartialEq)]
pub struct AvailableBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Option<BlobSidecarList<E>>,
    data_columns: Option<DataColumnSidecarList<E>>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
    blobs_available_timestamp: Option<Duration>,
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn __new_for_testing(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Option<BlobSidecarList<E>>,
        data_columns: Option<DataColumnSidecarList<E>>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            block_root,
            block,
            blobs,
            data_columns,
            blobs_available_timestamp: None,
            spec,
        }
    }

    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }

    pub fn blobs(&self) -> Option<&BlobSidecarList<E>> {
        self.blobs.as_ref()
    }

    pub fn blobs_available_timestamp(&self) -> Option<Duration> {
        self.blobs_available_timestamp
    }

    pub fn data_columns(&self) -> Option<&DataColumnSidecarList<E>> {
        self.data_columns.as_ref()
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(
        self,
    ) -> (
        Hash256,
        Arc<SignedBeaconBlock<E>>,
        Option<BlobSidecarList<E>>,
        Option<DataColumnSidecarList<E>>,
    ) {
        let AvailableBlock {
            block_root,
            block,
            blobs,
            data_columns,
            blobs_available_timestamp: _,
            ..
        } = self;
        (block_root, block, blobs, data_columns)
    }
}

#[derive(Debug, Clone)]
pub enum MaybeAvailableBlock<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-deneb blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending {
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
    },
}

impl<E: EthSpec> MaybeAvailableBlock<E> {
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match self {
            Self::Available(block) => block.block_cloned(),
            Self::AvailabilityPending { block, .. } => block.clone(),
        }
    }
}
