use crate::blob_verification::{verify_kzg_for_blob_list, GossipVerifiedBlob, KzgVerifiedBlobList};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
use crate::data_availability_checker::overflow_lru_cache::{
    DataAvailabilityCheckerInner, ReconstructColumnsDecision,
};
use crate::{metrics, BeaconChain, BeaconChainTypes, BeaconStore, CustodyContext};
use kzg::Kzg;
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tracing::{debug, error, info_span, Instrument};
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::{
    BlobSidecarList, ChainSpec, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    RuntimeVariableList, SignedBeaconBlock,
};

mod error;
mod overflow_lru_cache;
mod state_lru_cache;

use crate::data_column_verification::{
    verify_kzg_for_data_column_list_with_scoring, CustodyDataColumn, GossipVerifiedDataColumn,
    KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
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
    custody_context: Arc<CustodyContext>,
    spec: Arc<ChainSpec>,
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
        custody_context: Arc<CustodyContext>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        let inner = DataAvailabilityCheckerInner::new(
            OVERFLOW_LRU_CAPACITY,
            store,
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

    pub fn custody_context(&self) -> Arc<CustodyContext> {
        self.custody_context.clone()
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

    /// Check if the exact data column is in the availability cache.
    pub fn is_data_column_cached(
        &self,
        block_root: &Hash256,
        data_column: &DataColumnSidecar<T::EthSpec>,
    ) -> bool {
        self.availability_cache
            .peek_pending_components(block_root, |components| {
                components.is_some_and(|components| {
                    let cached_column_opt = components.get_cached_data_column(data_column.index);
                    cached_column_opt.is_some_and(|cached| *cached == *data_column)
                })
            })
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_blob(blob_id)
    }

    /// Get data columns for a block from the availability cache.
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.availability_cache.peek_data_columns(block_root)
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

        let verified_blobs = KzgVerifiedBlobList::new(
            blobs.into_vec().into_iter().flatten(),
            &self.kzg,
            seen_timestamp,
        )
        .map_err(AvailabilityCheckError::InvalidBlobs)?;

        self.availability_cache
            .put_kzg_verified_blobs(block_root, verified_blobs)
    }

    /// Put a list of custody columns received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    #[allow(clippy::type_complexity)]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Attributes fault to the specific peer that sent an invalid column
        let kzg_verified_columns = KzgVerifiedDataColumn::from_batch(custody_columns, &self.kzg)
            .map_err(AvailabilityCheckError::InvalidColumn)?;

        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.availability_cache
            .put_kzg_verified_data_columns(block_root, verified_custody_columns)
    }

    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_verified_blobs<
        I: IntoIterator<Item = GossipVerifiedBlob<T, O>>,
        O: ObservationStrategy,
    >(
        &self,
        block_root: Hash256,
        blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_kzg_verified_blobs(block_root, blobs.into_iter().map(|b| b.into_inner()))
    }

    /// Check if we've cached other data columns for this block. If it satisfies the custody requirement and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the data column sidecar.
    ///
    /// This should only accept gossip verified data columns, so we should not have to worry about dupes.
    pub fn put_gossip_verified_data_columns<
        O: ObservationStrategy,
        I: IntoIterator<Item = GossipVerifiedDataColumn<T, O>>,
    >(
        &self,
        block_root: Hash256,
        data_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let custody_columns = data_columns
            .into_iter()
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.availability_cache
            .put_kzg_verified_data_columns(block_root, custody_columns)
    }

    /// Check if we have all the blobs for a block. Returns `Availability` which has information
    /// about whether all components have been received or more are required.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_pending_executed_block(executed_block)
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
            return if let Some(blob_list) = blobs {
                verify_kzg_for_blob_list(blob_list.iter(), &self.kzg)
                    .map_err(AvailabilityCheckError::InvalidBlobs)?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blob_data: AvailableBlockData::Blobs(blob_list),
                    blobs_available_timestamp: None,
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
                )
                .map_err(AvailabilityCheckError::InvalidColumn)?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blob_data: AvailableBlockData::DataColumns(
                        data_column_list
                            .into_iter()
                            .map(|d| d.clone_arc())
                            .collect(),
                    ),
                    blobs_available_timestamp: None,
                    spec: self.spec.clone(),
                }))
            } else {
                Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
            };
        }

        Ok(MaybeAvailableBlock::Available(AvailableBlock {
            block_root,
            block,
            blob_data: AvailableBlockData::NoData,
            blobs_available_timestamp: None,
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
        let all_blobs = blocks
            .iter()
            .filter(|block| self.blobs_required_for_block(block.as_block()))
            // this clone is cheap as it's cloning an Arc
            .filter_map(|block| block.blobs().cloned())
            .flatten()
            .collect::<Vec<_>>();

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
            RuntimeVariableList::from_vec(all_data_columns, self.spec.number_of_columns as usize);

        // verify kzg for all data columns at once
        if !all_data_columns.is_empty() {
            // Attributes fault to the specific peer that sent an invalid column
            verify_kzg_for_data_column_list_with_scoring(all_data_columns.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;
        }

        for block in blocks {
            let (block_root, block, blobs, data_columns) = block.deconstruct();

            let maybe_available_block = if self.blobs_required_for_block(&block) {
                if let Some(blobs) = blobs {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blob_data: AvailableBlockData::Blobs(blobs),
                        blobs_available_timestamp: None,
                        spec: self.spec.clone(),
                    })
                } else {
                    MaybeAvailableBlock::AvailabilityPending { block_root, block }
                }
            } else if self.data_columns_required_for_block(&block) {
                if let Some(data_columns) = data_columns {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blob_data: AvailableBlockData::DataColumns(
                            data_columns.into_iter().map(|d| d.into_inner()).collect(),
                        ),
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
                    blob_data: AvailableBlockData::NoData,
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
            .is_some_and(|da_epoch| block_epoch >= da_epoch)
    }

    /// Returns `true` if the current epoch is greater than or equal to the `Deneb` epoch.
    pub fn is_deneb(&self) -> bool {
        self.slot_clock.now().is_some_and(|slot| {
            self.spec.deneb_fork_epoch.is_some_and(|deneb_epoch| {
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

        debug!(
            count = data_columns_to_publish.len(),
            ?block_root,
            %slot,
            "Reconstructed columns"
        );

        self.availability_cache
            .put_kzg_verified_data_columns(*block_root, data_columns_to_publish.clone())
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
            async move {
                availability_cache_maintenance_service(chain, overflow_cache)
                    .instrument(info_span!(
                        "DataAvailabilityChecker",
                        service = "data_availability_checker"
                    ))
                    .await
            },
            "availability_cache_service",
        );
    } else {
        debug!("Deneb fork not configured, not starting availability cache maintenance service");
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

                debug!("Availability cache maintenance service firing");
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

#[derive(Debug)]
pub enum AvailableBlockData<E: EthSpec> {
    /// Block is pre-Deneb or has zero blobs
    NoData,
    /// Block is post-Deneb, pre-PeerDAS and has more than zero blobs
    Blobs(BlobSidecarList<E>),
    /// Block is post-PeerDAS and has more than zero blobs
    DataColumns(DataColumnSidecarList<E>),
}

/// A fully available block that is ready to be imported into fork choice.
#[derive(Debug)]
pub struct AvailableBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    blob_data: AvailableBlockData<E>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
    blobs_available_timestamp: Option<Duration>,
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn __new_for_testing(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
        data: AvailableBlockData<E>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            block_root,
            block,
            blob_data: data,
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

    pub fn blobs_available_timestamp(&self) -> Option<Duration> {
        self.blobs_available_timestamp
    }

    pub fn data(&self) -> &AvailableBlockData<E> {
        &self.blob_data
    }

    pub fn has_blobs(&self) -> bool {
        match self.blob_data {
            AvailableBlockData::NoData => false,
            AvailableBlockData::Blobs(..) => true,
            AvailableBlockData::DataColumns(_) => false,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(self) -> (Hash256, Arc<SignedBeaconBlock<E>>, AvailableBlockData<E>) {
        let AvailableBlock {
            block_root,
            block,
            blob_data,
            ..
        } = self;
        (block_root, block, blob_data)
    }

    /// Only used for testing
    pub fn __clone_without_recv(&self) -> Result<Self, String> {
        Ok(Self {
            block_root: self.block_root,
            block: self.block.clone(),
            blob_data: match &self.blob_data {
                AvailableBlockData::NoData => AvailableBlockData::NoData,
                AvailableBlockData::Blobs(blobs) => AvailableBlockData::Blobs(blobs.clone()),
                AvailableBlockData::DataColumns(data_columns) => {
                    AvailableBlockData::DataColumns(data_columns.clone())
                }
            },
            blobs_available_timestamp: self.blobs_available_timestamp,
            spec: self.spec.clone(),
        })
    }
}

#[derive(Debug)]
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
