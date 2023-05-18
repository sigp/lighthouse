use crate::blob_verification::{
    verify_kzg_for_blob, verify_kzg_for_blob_list, AsBlock, BlockWrapper, GossipVerifiedBlob,
    KzgVerifiedBlob, KzgVerifiedBlobList, MaybeAvailableBlock,
};
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};

use crate::data_availability_checker::overflow_lru_cache::OverflowLRUCache;
use crate::{BeaconChain, BeaconChainTypes, BeaconStore};
use kzg::Error as KzgError;
use kzg::Kzg;
use slog::{debug, error};
use slot_clock::SlotClock;
use ssz_types::{Error, VariableList};
use state_processing::per_block_processing::deneb::deneb::verify_kzg_commitments_against_transactions;
use std::collections::hash_map::{Entry, OccupiedEntry};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use task_executor::TaskExecutor;
use strum::IntoStaticStr;
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::consts::deneb::MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS;
use types::ssz_tagged_signed_beacon_block;
use types::{
    BeaconBlockRef, BlobSidecarList, ChainSpec, Epoch, EthSpec, ExecPayload, FullPayload, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

mod overflow_lru_cache;

pub const OVERFLOW_LRU_CAPACITY: usize = 1024;

#[derive(Debug, IntoStaticStr)]
pub enum AvailabilityCheckError {
    Kzg(KzgError),
    KzgVerificationFailed,
    KzgNotInitialized,
    SszTypes(ssz_types::Error),
    MissingBlobs(Hash256),
    NumBlobsMismatch {
        num_kzg_commitments: usize,
        num_blobs: usize,
    },
    TxKzgCommitmentMismatch(String),
    KzgCommitmentMismatch {
        blob_index: u64,
    },
    IncorrectFork,
    BlobIndexInvalid(u64),
    StoreError(store::Error),
    DecodeError(ssz::DecodeError),
    BlockBlobRootMismatch {
        block_root: Hash256,
        blob_block_root: Hash256,
    },
    UnorderedBlobs {
        expected_index: u64,
        blob_index: u64,
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

/// This cache contains
///  - blobs that have been gossip verified
///  - commitments for blocks that have been gossip verified, but the commitments themselves
///    have not been verified against blobs
///  - blocks that have been fully verified and only require a data availability check
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    availability_cache: Arc<OverflowLRUCache<T>>,
    slot_clock: T::SlotClock,
    kzg: Option<Arc<Kzg>>,
    spec: ChainSpec,
}

/// Caches partially available blobs and execution verified blocks corresponding
/// to a given `block_hash` that are received over gossip.
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
struct ReceivedComponents<T: EthSpec> {
    verified_blobs: FixedVector<Option<KzgVerifiedBlob<T>>, T::MaxBlobsPerBlock>,
    executed_block: Option<AvailabilityPendingExecutedBlock<T>>,
}

impl<T: EthSpec> ReceivedComponents<T> {
    fn new_from_blobs(blobs: &[KzgVerifiedBlob<T>]) -> Self {
        let mut verified_blobs = FixedVector::<_, _>::default();
        for blob in blobs {
            // TODO: verify that we've already ensured the blob index < T::MaxBlobsPerBlock
            if let Some(mut_maybe_blob) = verified_blobs.get_mut(blob.blob_index() as usize) {
                *mut_maybe_blob = Some(blob.clone());
            }
        }

        Self {
            verified_blobs,
            executed_block: None,
        }
    }

    fn new_from_block(block: AvailabilityPendingExecutedBlock<T>) -> Self {
        Self {
            verified_blobs: <_>::default(),
            executed_block: Some(block),
        }
    }

    /// Returns `true` if the cache has all blobs corresponding to the
    /// kzg commitments in the block.
    fn has_all_blobs(&self, block: &AvailabilityPendingExecutedBlock<T>) -> bool {
        for i in 0..block.num_blobs_expected() {
            if self
                .verified_blobs
                .get(i)
                .map(|maybe_blob| maybe_blob.is_none())
                .unwrap_or(true)
            {
                return false;
            }
        }
        true
    }
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
#[derive(Debug, PartialEq)]
pub enum Availability<T: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

impl<T: EthSpec> Availability<T> {
    /// Returns all the blob identifiers associated with an  `AvailableBlock`.
    /// Returns `None` if avaiability hasn't been fully satisfied yet.
    pub fn get_available_blob_ids(&self) -> Option<Vec<BlobIdentifier>> {
        if let Self::Available(block) = self {
            Some(block.get_all_blob_ids())
        } else {
            None
        }
    }
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        slot_clock: T::SlotClock,
        kzg: Option<Arc<Kzg>>,
        store: BeaconStore<T>,
        spec: ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_cache = OverflowLRUCache::new(OVERFLOW_LRU_CAPACITY, store)?;
        Ok(Self {
            availability_cache: Arc::new(overflow_cache),
            slot_clock,
            kzg,
            spec,
        })
    }

    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.availability_cache
            .read()
            .get(block_root)
            .map_or(false, |cache| cache.executed_block.is_some())
    }

    pub fn get_missing_blob_ids_checking_cache(
        &self,
        block_root: Hash256,
    ) -> Option<Vec<BlobIdentifier>> {
        let guard = self.availability_cache.read();
        let (block, blob_indices) = guard
            .get(&block_root)
            .map(|cache| {
                let block_opt = cache
                    .executed_block
                    .as_ref()
                    .map(|block| &block.block.block);
                let blobs = cache
                    .verified_blobs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, maybe_blob)| maybe_blob.as_ref().map(|_| i))
                    .collect::<HashSet<_>>();
                (block_opt, blobs)
            })
            .unwrap_or_default();
        self.get_missing_blob_ids(block_root, block, Some(blob_indices))
    }

    /// A `None` indicates blobs are not required.
    ///
    /// If there's no block, all possible ids will be returned that don't exist in the given blobs.
    /// If there no blobs, all possible ids will be returned.
    pub fn get_missing_blob_ids(
        &self,
        block_root: Hash256,
        block_opt: Option<&Arc<SignedBeaconBlock<T>>>,
        blobs_opt: Option<HashSet<usize>>,
    ) -> Option<Vec<BlobIdentifier>> {
        let epoch = self.slot_clock.now()?.epoch(T::slots_per_epoch());

        self.da_check_required(epoch).then(|| {
            block_opt
                .map(|block| {
                    block.get_filtered_blob_ids(Some(block_root), |i, _| {
                        blobs_opt.as_ref().map_or(true, |blobs| !blobs.contains(&i))
                    })
                })
                .unwrap_or_else(|| {
                    let mut blob_ids = Vec::with_capacity(T::max_blobs_per_block());
                    for i in 0..T::max_blobs_per_block() {
                        if blobs_opt.as_ref().map_or(true, |blobs| !blobs.contains(&i)) {
                            blob_ids.push(BlobIdentifier {
                                block_root,
                                index: i as u64,
                            });
                        }
                    }
                    blob_ids
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

    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        // TODO(sean) we may duplicated kzg verification on some blobs we already have cached so we could optimize this

        let mut verified_blobs = vec![];
        if let Some(kzg) = self.kzg.as_ref() {
            for blob in blobs.iter().flatten() {
                verified_blobs.push(verify_kzg_for_blob(blob.clone(), kzg)?)
            }
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        self.put_kzg_verified_blobs(block_root, &verified_blobs)
    }

    /// This first validates the KZG commitments included in the blob sidecar.
    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_blob(
        &self,
        gossip_blob: GossipVerifiedBlob<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Verify the KZG commitments.
        let kzg_verified_blob = if let Some(kzg) = self.kzg.as_ref() {
            verify_kzg_for_blob(gossip_blob.to_blob(), kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        self.availability_cache
            .put_kzg_verified_blob(kzg_verified_blob)
        self.put_kzg_verified_blobs(kzg_verified_blob.block_root(), &[kzg_verified_blob])
    }

    fn put_kzg_verified_blobs(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: &[KzgVerifiedBlob<T>],
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        for blob in kzg_verified_blobs {
            let blob_block_root = blob.block_root();
            if blob_block_root != block_root {
                return Err(AvailabilityCheckError::BlockBlobRootMismatch {
                    block_root,
                    blob_block_root,
                });
            }
        }

        let availability = match self.availability_cache.write().entry(block_root) {
            Entry::Occupied(mut occupied_entry) => {
                // All blobs reaching this cache should be gossip verified and gossip verification
                // should filter duplicates, as well as validate indices.
                let received_components = occupied_entry.get_mut();

                for kzg_verified_blob in kzg_verified_blobs {
                    if let Some(maybe_verified_blob) = received_components
                        .verified_blobs
                        .get_mut(kzg_verified_blob.blob_index() as usize)
                    {
                        *maybe_verified_blob = Some(kzg_verified_blob.clone())
                    }
                }

                if let Some(executed_block) = received_components.executed_block.take() {
                    self.check_block_availability_maybe_cache(occupied_entry, executed_block)?
                } else {
                    Availability::MissingComponents(block_root)
                }
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(ReceivedComponents::new_from_blobs(kzg_verified_blobs));
                Availability::MissingComponents(block_root)
            }
        };

        Ok(availability)
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_pending_executed_block(executed_block)
    }

    /// Checks if the provided `executed_block` contains all required blobs to be considered an
    /// `AvailableBlock` based on blobs that are cached.
    ///
    /// Returns an error if there was an error when matching the block commitments against blob commitments.
    ///
    /// Returns `Ok(Availability::Available(_))` if all blobs for the block are present in cache.
    /// Returns `Ok(Availability::PendingBlobs(_))` if all corresponding blobs have not been received in the cache.
    fn check_block_availability_maybe_cache(
        &self,
        mut occupied_entry: OccupiedEntry<Hash256, ReceivedComponents<T>>,
        executed_block: AvailabilityPendingExecutedBlock<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        if occupied_entry.get().has_all_blobs(&executed_block) {
            let num_blobs_expected = executed_block.num_blobs_expected();
            let block_root = executed_block.import_data.block_root;
            let AvailabilityPendingExecutedBlock {
                block,
                import_data,
                payload_verification_outcome,
            } = executed_block;

            let ReceivedComponents {
                verified_blobs,
                executed_block: _,
            } = occupied_entry.remove();

            let verified_blobs = Vec::from(verified_blobs)
                .into_iter()
                .take(num_blobs_expected)
                .map(|maybe_blob| {
                    maybe_blob.ok_or(AvailabilityCheckError::MissingBlobs(block_root))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let available_block = self.make_available(block, verified_blobs)?;
            Ok(Availability::Available(Box::new(
                AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ),
            )))
        } else {
            let received_components = occupied_entry.get_mut();

            let block_root = executed_block.import_data.block_root;

            let _ = received_components.executed_block.insert(executed_block);

            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Checks if a block is available, returns a `MaybeAvailableBlock` that may include the fully
    /// available block.
    pub fn check_availability(
        &self,
        block: BlockWrapper<T::EthSpec>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        match block {
            BlockWrapper::Block(block) => self.check_availability_without_blobs(block),
            BlockWrapper::BlockAndBlobs(block, blob_list) => {
                let kzg = self
                    .kzg
                    .as_ref()
                    .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
                let filtered_blobs = blob_list.iter().flatten().cloned().collect();
                let verified_blobs = verify_kzg_for_blob_list(filtered_blobs, kzg)?;

                Ok(MaybeAvailableBlock::Available(
                    self.check_availability_with_blobs(block, verified_blobs)?,
                ))
            }
        }
    }

    /// Checks if a block is available, returning an error if the block is not immediately available.
    /// Does not access the gossip cache.
    pub fn try_check_availability(
        &self,
        block: BlockWrapper<T::EthSpec>,
    ) -> Result<AvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        match block {
            BlockWrapper::Block(block) => {
                let blob_requirements = self.get_blob_requirements(&block)?;
                let blobs = match blob_requirements {
                    BlobRequirements::EmptyBlobs => VerifiedBlobs::EmptyBlobs,
                    BlobRequirements::NotRequired => VerifiedBlobs::NotRequired,
                    BlobRequirements::PreDeneb => VerifiedBlobs::PreDeneb,
                    BlobRequirements::Required => return Err(AvailabilityCheckError::MissingBlobs),
                };
                Ok(AvailableBlock { block, blobs })
            }
            BlockWrapper::BlockAndBlobs(_, _) => Err(AvailabilityCheckError::Pending),
        }
    }

    /// Verifies a block against a set of KZG verified blobs. Returns an AvailableBlock if block's
    /// commitments are consistent with the provided verified blob commitments.
    pub fn check_availability_with_blobs(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        blobs: KzgVerifiedBlobList<T::EthSpec>,
    ) -> Result<AvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        match self.check_availability_without_blobs(block)? {
            MaybeAvailableBlock::Available(block) => Ok(block),
            MaybeAvailableBlock::AvailabilityPending(pending_block) => {
                pending_block.make_available(blobs)
            }
        }
    }

    /// Verifies a block as much as possible, returning a MaybeAvailableBlock enum that may include
    /// an AvailableBlock if no blobs are required. Otherwise this will return an AvailabilityPendingBlock.
    pub fn check_availability_without_blobs(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        let blob_requirements = self.get_blob_requirements(&block)?;
        let blobs = match blob_requirements {
            BlobRequirements::EmptyBlobs => VerifiedBlobs::EmptyBlobs,
            BlobRequirements::NotRequired => VerifiedBlobs::NotRequired,
            BlobRequirements::PreDeneb => VerifiedBlobs::PreDeneb,
            BlobRequirements::Required => {
                return Ok(MaybeAvailableBlock::AvailabilityPending(
                    AvailabilityPendingBlock { block },
                ))
            }
        };
        Ok(MaybeAvailableBlock::Available(AvailableBlock {
            block,
            blobs,
        }))
    }

    /// Determines the blob requirements for a block. Answers the question: "Does this block require
    /// blobs?".
    fn get_blob_requirements(
        &self,
        block: &Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    ) -> Result<BlobRequirements, AvailabilityCheckError> {
        let verified_blobs = if let (Ok(block_kzg_commitments), Ok(payload)) = (
            block.message().body().blob_kzg_commitments(),
            block.message().body().execution_payload(),
        ) {
            if let Some(transactions) = payload.transactions() {
                let verified = verify_kzg_commitments_against_transactions::<T::EthSpec>(
                    transactions,
                    block_kzg_commitments,
                )
                .map_err(|e| AvailabilityCheckError::TxKzgCommitmentMismatch(format!("{e:?}")))?;
                if !verified {
                    return Err(AvailabilityCheckError::TxKzgCommitmentMismatch(
                        "a commitment and version didn't match".to_string(),
                    ));
                }
            }

            if self.da_check_required(block.epoch()) {
                if block_kzg_commitments.is_empty() {
                    BlobRequirements::EmptyBlobs
                } else {
                    BlobRequirements::Required
                }
            } else {
                BlobRequirements::NotRequired
            }
        } else {
            BlobRequirements::PreDeneb
        };
        Ok(verified_blobs)
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
    pub fn da_check_required(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .map_or(false, |da_epoch| block_epoch >= da_epoch)
    }

    /// Persist all in memory components to disk
    pub fn persist_all(&self) -> Result<(), AvailabilityCheckError> {
        self.availability_cache.write_all_to_disk()
    }
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

pub enum BlobRequirements {
    Required,
    /// This block is from outside the data availability boundary so doesn't require
    /// a data availability check.
    NotRequired,
    /// The block's `kzg_commitments` field is empty so it does not contain any blobs.
    EmptyBlobs,
    /// This is a block prior to the 4844 fork, so doesn't require any blobs
    PreDeneb,
}

/// A wrapper over a `SignedBeaconBlock` where we have not verified availability of
/// corresponding `BlobSidecar`s and hence, is not ready for import into fork choice.
///
/// Note: This wrapper does not necessarily correspond to a pre-deneb block as a pre-deneb
/// block that is ready for import will be of type `AvailableBlock` with its `blobs` field
/// set to `VerifiedBlobs::PreDeneb`.
#[derive(Clone, Debug, PartialEq)]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
}

impl<E: EthSpec> AvailabilityPendingBlock<E> {
    pub fn slot(&self) -> Slot {
        self.block.slot()
    }
    pub fn num_blobs_expected(&self) -> usize {
        self.block.num_expected_blobs()
    }

    pub fn get_all_blob_ids(&self, block_root: Option<Hash256>) -> Vec<BlobIdentifier> {
        self.block.get_expected_blob_ids(block_root)
    }

    pub fn get_filtered_blob_ids(
        &self,
        block_root: Option<Hash256>,
        filter: impl Fn(usize, Hash256) -> bool,
    ) -> Vec<BlobIdentifier> {
        self.block.get_filtered_blob_ids(block_root, filter)
    }
}

impl<E: EthSpec> AvailabilityPendingBlock<E> {
    pub fn to_block(self) -> Arc<SignedBeaconBlock<E>> {
        self.block
    }
    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }
    pub fn kzg_commitments(&self) -> Result<&KzgCommitments<E>, AvailabilityCheckError> {
        self.block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_| AvailabilityCheckError::IncorrectFork)
    }

    /// Verifies an AvailabilityPendingBlock against a set of KZG verified blobs.
    /// This does not check whether a block *should* have blobs, these checks should must have been
    /// completed when producing the `AvailabilityPendingBlock`.
    pub fn make_available(
        self,
        blobs: Vec<KzgVerifiedBlob<E>>,
    ) -> Result<AvailableBlock<E>, AvailabilityCheckError> {
        let block_kzg_commitments = self.kzg_commitments()?;
        if blobs.len() != block_kzg_commitments.len() {
            return Err(AvailabilityCheckError::NumBlobsMismatch {
                num_kzg_commitments: block_kzg_commitments.len(),
                num_blobs: blobs.len(),
            });
        }

        for (block_commitment, blob) in block_kzg_commitments.iter().zip(blobs.iter()) {
            if *block_commitment != blob.kzg_commitment() {
                return Err(AvailabilityCheckError::KzgCommitmentMismatch {
                    blob_index: blob.as_blob().index,
                });
            }
        }

        let blobs = VariableList::new(blobs.into_iter().map(|blob| blob.to_blob()).collect())?;

        Ok(AvailableBlock {
            block: self.block,
            blobs: VerifiedBlobs::Available(blobs),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerifiedBlobs<E: EthSpec> {
    /// These blobs are available.
    Available(BlobSidecarList<E>),
    /// This block is from outside the data availability boundary so doesn't require
    /// a data availability check.
    NotRequired,
    /// The block's `kzg_commitments` field is empty so it does not contain any blobs.
    EmptyBlobs,
    /// This is a block prior to the 4844 fork, so doesn't require any blobs
    PreDeneb,
}

/// A fully available block that is ready to be imported into fork choice.
#[derive(Clone, Debug, PartialEq)]
pub struct AvailableBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    blobs: VerifiedBlobs<E>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn da_check_required(&self) -> bool {
        match self.blobs {
            VerifiedBlobs::PreDeneb | VerifiedBlobs::NotRequired => false,
            VerifiedBlobs::EmptyBlobs | VerifiedBlobs::Available(_) => true,
        }
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<BlobSidecarList<E>>) {
        match self.blobs {
            VerifiedBlobs::EmptyBlobs | VerifiedBlobs::NotRequired | VerifiedBlobs::PreDeneb => {
                (self.block, None)
            }
            VerifiedBlobs::Available(blobs) => (self.block, Some(blobs)),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.block.slot()
    }

    fn epoch(&self) -> Epoch {
        self.block.epoch()
    }

    fn parent_root(&self) -> Hash256 {
        self.block.parent_root()
    }

    fn state_root(&self) -> Hash256 {
        self.block.state_root()
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.block.signed_block_header()
    }

    fn message(&self) -> BeaconBlockRef<E> {
        self.block.message()
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }

    fn canonical_root(&self) -> Hash256 {
        self.block.canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        let (block, blobs_opt) = self.deconstruct();
        if let Some(blobs) = blobs_opt {
            let blobs_vec = blobs.iter().cloned().map(Option::Some).collect::<Vec<_>>();
            BlockWrapper::BlockAndBlobs(block, FixedVector::from(blobs_vec))
        } else {
            BlockWrapper::Block(block)
        }
    }
}

// The standard implementation of Encode for SignedBeaconBlock
// requires us to use ssz(enum_behaviour = "transparent"). This
// prevents us from implementing Decode. We need to use a
// custom Encode and Decode in this wrapper object that essentially
// encodes it as if it were ssz(enum_behaviour = "union")
impl<E: EthSpec> ssz::Encode for AvailabilityPendingBlock<E> {
    fn is_ssz_fixed_len() -> bool {
        ssz_tagged_signed_beacon_block::encode::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        ssz_tagged_signed_beacon_block::encode::ssz_append(self.block.as_ref(), buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        ssz_tagged_signed_beacon_block::encode::ssz_bytes_len(self.block.as_ref())
    }
}

impl<E: EthSpec> ssz::Decode for AvailabilityPendingBlock<E> {
    fn is_ssz_fixed_len() -> bool {
        ssz_tagged_signed_beacon_block::decode::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self {
            block: Arc::new(ssz_tagged_signed_beacon_block::decode::from_ssz_bytes(
                bytes,
            )?),
        })
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn check_encode_decode_availability_pending_block() {
        // todo.. (difficult to create default beacon blocks to test)
    }
}
