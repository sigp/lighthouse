use crate::blob_verification::{verify_kzg_for_blob, verify_kzg_for_blob_list, GossipVerifiedBlob};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
pub use crate::data_availability_checker::availability_view::AvailabilityView;
use crate::data_availability_checker::overflow_lru_cache::OverflowLRUCache;
use crate::data_availability_checker::processing_cache::ProcessingCache;
use crate::{BeaconChain, BeaconChainTypes, BeaconStore};
use kzg::Error as KzgError;
use kzg::Kzg;
use parking_lot::RwLock;
pub use processing_cache::ProcessingInfo;
use slog::{debug, error};
use slot_clock::SlotClock;
use ssz_types::Error;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use strum::IntoStaticStr;
use task_executor::TaskExecutor;
use types::beacon_block_body::{KzgCommitmentOpts, KzgCommitments};
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::consts::deneb::MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS;
use types::{BlobSidecarList, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

mod availability_view;
mod overflow_lru_cache;
mod processing_cache;

/// The LRU Cache stores `PendingComponents` which can store up to
/// `MAX_BLOBS_PER_BLOCK = 6` blobs each. A `BlobSidecar` is 0.131256 MB. So
/// the maximum size of a `PendingComponents` is ~ 0.787536 MB. Setting this
/// to 1024 means the maximum size of the cache is ~ 0.8 GB. But the cache
/// will target a size of less than 75% of capacity.
pub const OVERFLOW_LRU_CAPACITY: usize = 1024;

#[derive(Debug, IntoStaticStr)]
pub enum AvailabilityCheckError {
    Kzg(KzgError),
    KzgNotInitialized,
    KzgVerificationFailed,
    Unexpected,
    SszTypes(ssz_types::Error),
    MissingBlobs,
    BlobIndexInvalid(u64),
    StoreError(store::Error),
    DecodeError(ssz::DecodeError),
    InconsistentBlobBlockRoots {
        block_root: Hash256,
        blob_block_root: Hash256,
    },
}

impl From<ssz_types::Error> for AvailabilityCheckError {
    fn from(value: Error) -> Self {
        Self::SszTypes(value)
    }
}

impl From<store::Error> for AvailabilityCheckError {
    fn from(value: store::Error) -> Self {
        Self::StoreError(value)
    }
}

impl From<ssz::DecodeError> for AvailabilityCheckError {
    fn from(value: ssz::DecodeError) -> Self {
        Self::DecodeError(value)
    }
}

/// This includes a cache for any blocks or blobs that have been received over gossip or RPC
/// and are awaiting more components before they can be imported. Additionally the
/// `DataAvailabilityChecker` is responsible for KZG verification of block components as well as
/// checking whether a "availability check" is required at all.
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    processing_cache: RwLock<ProcessingCache<T::EthSpec>>,
    availability_cache: Arc<OverflowLRUCache<T>>,
    slot_clock: T::SlotClock,
    kzg: Option<Arc<Kzg<<T::EthSpec as EthSpec>::Kzg>>>,
    spec: ChainSpec,
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
#[derive(PartialEq)]
pub enum Availability<T: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

impl<T: EthSpec> Debug for Availability<T> {
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
        kzg: Option<Arc<Kzg<<T::EthSpec as EthSpec>::Kzg>>>,
        store: BeaconStore<T>,
        spec: ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_cache = OverflowLRUCache::new(OVERFLOW_LRU_CAPACITY, store)?;
        Ok(Self {
            processing_cache: <_>::default(),
            availability_cache: Arc::new(overflow_cache),
            slot_clock,
            kzg,
            spec,
        })
    }

    /// Checks if the given block root is cached.
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.processing_cache.read().has_block(block_root)
    }

    /// Checks which blob ids are still required for a given block root, taking any cached
    /// components into consideration.
    pub fn get_missing_blob_ids_checking_cache(
        &self,
        block_root: Hash256,
    ) -> Option<Vec<BlobIdentifier>> {
        let guard = self.processing_cache.read();
        self.get_missing_blob_ids(block_root, guard.get(&block_root)?)
    }

    /// A `None` indicates blobs are not required.
    ///
    /// If there's no block, all possible ids will be returned that don't exist in the given blobs.
    /// If there no blobs, all possible ids will be returned.
    pub fn get_missing_blob_ids(
        &self,
        block_root: Hash256,
        processing_info: &ProcessingInfo<T::EthSpec>,
    ) -> Option<Vec<BlobIdentifier>> {
        let epoch = self.slot_clock.now()?.epoch(T::EthSpec::slots_per_epoch());

        self.da_check_required_for_epoch(epoch)
            .then(|| processing_info.get_missing_blob_ids(block_root))
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
        let mut verified_blobs = vec![];
        if let Some(kzg) = self.kzg.as_ref() {
            for blob in blobs.iter().flatten() {
                verified_blobs.push(verify_kzg_for_blob(blob.clone(), kzg)?)
            }
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };
        self.availability_cache
            .put_kzg_verified_blobs(block_root, &verified_blobs)
    }

    /// This first validates the KZG commitments included in the blob sidecar.
    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_blob(
        &self,
        gossip_blob: GossipVerifiedBlob<T>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Verify the KZG commitments.
        let kzg_verified_blob = if let Some(kzg) = self.kzg.as_ref() {
            verify_kzg_for_blob(gossip_blob.to_blob(), kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        self.availability_cache
            .put_kzg_verified_blobs(kzg_verified_blob.block_root(), &[kzg_verified_blob])
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

    /// Checks if a block is available, returns a `MaybeAvailableBlock` that may include the fully
    /// available block.
    pub fn check_rpc_block_availability(
        &self,
        block: RpcBlock<T::EthSpec>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        let (block, blobs) = block.deconstruct();
        match blobs {
            None => {
                if self.blobs_required_for_block(&block) {
                    Ok(MaybeAvailableBlock::AvailabilityPending(block))
                } else {
                    Ok(MaybeAvailableBlock::Available(AvailableBlock {
                        block,
                        blobs: None,
                    }))
                }
            }
            Some(blob_list) => {
                let verified_blobs = if self.blobs_required_for_block(&block) {
                    let kzg = self
                        .kzg
                        .as_ref()
                        .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
                    verify_kzg_for_blob_list(&blob_list, kzg)?;
                    Some(blob_list)
                } else {
                    None
                };
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block,
                    blobs: verified_blobs,
                }))
            }
        }
    }

    /// Determines the blob requirements for a block. Answers the question: "Does this block require
    /// blobs?".
    fn blobs_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        let block_within_da_period = self.da_check_required_for_epoch(block.epoch());
        let block_has_kzg_commitments = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(false, |commitments| !commitments.is_empty());
        block_within_da_period && block_has_kzg_commitments
    }

    pub fn notify_block_commitments(
        &self,
        block_root: Hash256,
        commitments: KzgCommitments<T::EthSpec>,
    ) {
        self.processing_cache
            .write()
            .entry(block_root)
            .or_insert_with(ProcessingInfo::default)
            .merge_block(commitments);
    }

    pub fn notify_blob_commitments(
        &self,
        block_root: Hash256,
        blobs: KzgCommitmentOpts<T::EthSpec>,
    ) {
        self.processing_cache
            .write()
            .entry(block_root)
            .or_insert_with(ProcessingInfo::default)
            .merge_blobs(blobs);
    }

    pub fn remove_notified(&self, block_root: &Hash256) {
        self.processing_cache.write().remove(block_root)
    }

    pub fn get_delayed_lookups(&self, slot: Slot) -> Vec<Hash256> {
        self.processing_cache
            .read()
            .incomplete_lookups_for_slot(slot)
    }

    pub fn should_delay_lookup(&self, slot: Slot) -> bool {
        if !self.is_deneb() {
            return false;
        }

        let maximum_gossip_clock_disparity = self.spec.maximum_gossip_clock_disparity();
        let earliest_slot = self
            .slot_clock
            .now_with_past_tolerance(maximum_gossip_clock_disparity);
        let latest_slot = self
            .slot_clock
            .now_with_future_tolerance(maximum_gossip_clock_disparity);
        if let (Some(earliest_slot), Some(latest_slot)) = (earliest_slot, latest_slot) {
            let msg_for_current_slot = slot >= earliest_slot && slot <= latest_slot;
            let delay_threshold_unmet = self
                .slot_clock
                .millis_from_current_slot_start()
                .map_or(false, |millis_into_slot| {
                    millis_into_slot < self.slot_clock.single_lookup_delay()
                });
            msg_for_current_slot && delay_threshold_unmet
        } else {
            false
        }
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
                        current_epoch.saturating_sub(*MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS),
                    )
                })
        })
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

    /// Persist all in memory components to disk
    pub fn persist_all(&self) -> Result<(), AvailabilityCheckError> {
        self.availability_cache.write_all_to_disk()
    }
}

/// Makes the following checks to ensure that the list of blobs correspond block:
///
/// * Check that a block is post-deneb
/// * Checks that the number of blobs is equal to the length of kzg commitments in the list
/// * Checks that the index, slot, root and kzg_commitment in the block match the blobs in the correct order
///
/// Returns `Ok(())` if all consistency checks pass and an error otherwise.
pub fn consistency_checks<E: EthSpec>(
    block: &SignedBeaconBlock<E>,
    blobs: &[Arc<BlobSidecar<E>>],
) -> Result<(), AvailabilityCheckError> {
    let Ok(block_kzg_commitments) = block.message().body().blob_kzg_commitments() else {
        return Ok(());
    };

    if block_kzg_commitments.is_empty() {
        return Ok(());
    }

    if blobs.len() != block_kzg_commitments.len() {
        return Err(AvailabilityCheckError::MissingBlobs);
    }

    Ok(())
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
    overflow_cache: Arc<OverflowLRUCache<T>>,
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

                let deneb_fork_epoch = match chain.spec.deneb_fork_epoch {
                    Some(epoch) => epoch,
                    None => break, // shutdown service if deneb fork epoch not set
                };

                debug!(
                    chain.log,
                    "Availability cache maintenance service firing";
                );

                let current_epoch = match chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                {
                    Some(epoch) => epoch,
                    None => continue, // we'll have to try again next time I suppose..
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
                        current_epoch.saturating_sub(*MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS),
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
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Option<BlobSidecarList<E>>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }

    pub fn blobs(&self) -> Option<&BlobSidecarList<E>> {
        self.blobs.as_ref()
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<BlobSidecarList<E>>) {
        let AvailableBlock { block, blobs } = self;
        (block, blobs)
    }
}

#[derive(Debug, Clone)]
pub enum MaybeAvailableBlock<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-deneb blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending(Arc<SignedBeaconBlock<E>>),
}
