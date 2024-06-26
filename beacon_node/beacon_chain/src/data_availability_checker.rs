use crate::blob_verification::{verify_kzg_for_blob_list, GossipVerifiedBlob, KzgVerifiedBlobList};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
use crate::data_availability_checker::overflow_lru_cache::DataAvailabilityCheckerInner;
use crate::{BeaconChain, BeaconChainTypes, BeaconStore};
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
use types::{BlobSidecarList, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock};

mod error;
mod overflow_lru_cache;
mod state_lru_cache;

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
    kzg: Option<Arc<Kzg>>,
    log: Logger,
    spec: ChainSpec,
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
        kzg: Option<Arc<Kzg>>,
        store: BeaconStore<T>,
        log: &Logger,
        spec: ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_cache =
            DataAvailabilityCheckerInner::new(OVERFLOW_LRU_CAPACITY, store, spec.clone())?;
        Ok(Self {
            availability_cache: Arc::new(overflow_cache),
            slot_clock,
            log: log.clone(),
            kzg,
            spec,
        })
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

    /// Return the set of imported blob indexes for `block_root`. Returns None if there is no block
    /// component for `block_root`.
    pub fn imported_blob_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
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

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_blob(blob_id)
    }

    /// Put a list of blobs received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let Some(kzg) = self.kzg.as_ref() else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        let seen_timestamp = self
            .slot_clock
            .now_duration()
            .ok_or(AvailabilityCheckError::SlotClockError)?;

        let verified_blobs =
            KzgVerifiedBlobList::new(Vec::from(blobs).into_iter().flatten(), kzg, seen_timestamp)
                .map_err(AvailabilityCheckError::Kzg)?;

        self.availability_cache
            .put_kzg_verified_blobs(block_root, verified_blobs)
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
        self.availability_cache
            .put_kzg_verified_blobs(gossip_blob.block_root(), vec![gossip_blob.into_inner()])
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
        let (block_root, block, blobs) = block.deconstruct();
        match blobs {
            None => {
                if self.blobs_required_for_block(&block) {
                    Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
                } else {
                    Ok(MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs: None,
                        blobs_available_timestamp: None,
                    }))
                }
            }
            Some(blob_list) => {
                let verified_blobs = if self.blobs_required_for_block(&block) {
                    let kzg = self
                        .kzg
                        .as_ref()
                        .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
                    verify_kzg_for_blob_list(blob_list.iter(), kzg)
                        .map_err(AvailabilityCheckError::Kzg)?;
                    Some(blob_list)
                } else {
                    None
                };
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blobs: verified_blobs,
                    blobs_available_timestamp: None,
                }))
            }
        }
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
            let kzg = self
                .kzg
                .as_ref()
                .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
            verify_kzg_for_blob_list(all_blobs.iter(), kzg)?;
        }

        for block in blocks {
            let (block_root, block, blobs) = block.deconstruct();
            match blobs {
                None => {
                    if self.blobs_required_for_block(&block) {
                        results.push(MaybeAvailableBlock::AvailabilityPending { block_root, block })
                    } else {
                        results.push(MaybeAvailableBlock::Available(AvailableBlock {
                            block_root,
                            block,
                            blobs: None,
                            blobs_available_timestamp: None,
                        }))
                    }
                }
                Some(blob_list) => {
                    let verified_blobs = if self.blobs_required_for_block(&block) {
                        Some(blob_list)
                    } else {
                        None
                    };
                    // already verified kzg for all blobs
                    results.push(MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs: verified_blobs,
                        blobs_available_timestamp: None,
                    }))
                }
            }
        }

        Ok(results)
    }

    /// Determines the blob requirements for a block. If the block is pre-deneb, no blobs are required.
    /// If the block's epoch is from prior to the data availability boundary, no blobs are required.
    fn blobs_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.da_check_required_for_epoch(block.epoch())
    }

    /// The epoch at which we require a data availability check in block processing.
    /// `None` if the `Deneb` fork is disabled.
    pub fn data_availability_boundary(&self) -> Option<Epoch> {
        self.spec.deneb_fork_epoch.and_then(|fork_epoch| {
            self.slot_clock
                .now()
                .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                .map(|current_epoch| {
                    std::cmp::max(
                        fork_epoch,
                        current_epoch
                            .saturating_sub(self.spec.min_epochs_for_blob_sidecars_requests),
                    )
                })
        })
    }

    /// Returns true if the given epoch lies within the da boundary and false otherwise.
    pub fn da_check_required_for_epoch(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .map_or(false, |da_epoch| block_epoch >= da_epoch)
    }

    pub fn da_check_required_for_current_epoch(&self) -> bool {
        let Some(current_slot) = self.slot_clock.now_or_genesis() else {
            error!(
                self.log,
                "Failed to read slot clock when checking for missing blob ids"
            );
            return false;
        };

        self.da_check_required_for_epoch(current_slot.epoch(T::EthSpec::slots_per_epoch()))
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

/// A fully available block that is ready to be imported into fork choice.
#[derive(Clone, Debug, PartialEq)]
pub struct AvailableBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Option<BlobSidecarList<E>>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
    blobs_available_timestamp: Option<Duration>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn __new_for_testing(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Option<BlobSidecarList<E>>,
    ) -> Self {
        Self {
            block_root,
            block,
            blobs,
            blobs_available_timestamp: None,
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

    pub fn deconstruct(
        self,
    ) -> (
        Hash256,
        Arc<SignedBeaconBlock<E>>,
        Option<BlobSidecarList<E>>,
    ) {
        let AvailableBlock {
            block_root,
            block,
            blobs,
            blobs_available_timestamp: _,
        } = self;
        (block_root, block, blobs)
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
