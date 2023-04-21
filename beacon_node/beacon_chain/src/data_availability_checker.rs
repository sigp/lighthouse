use crate::blob_verification::{
    verify_kzg_for_blob, verify_kzg_for_blob_list, AsBlock, BlockWrapper, GossipVerifiedBlob,
    KzgVerifiedBlob, KzgVerifiedBlobList, MaybeAvailableBlock,
};
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};

use kzg::Error as KzgError;
use kzg::Kzg;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use ssz_types::{Error, FixedVector, VariableList};
use state_processing::per_block_processing::deneb::deneb::verify_kzg_commitments_against_transactions;
use std::collections::hash_map::{Entry, OccupiedEntry};
use std::collections::HashMap;
use std::sync::Arc;
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::consts::deneb::MIN_EPOCHS_FOR_BLOBS_SIDECARS_REQUESTS;
use types::{
    BeaconBlockRef, BlobSidecarList, ChainSpec, Epoch, EthSpec, ExecPayload, FullPayload, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

#[derive(Debug)]
pub enum AvailabilityCheckError {
    DuplicateBlob(Hash256),
    Kzg(KzgError),
    KzgVerificationFailed,
    KzgNotInitialized,
    SszTypes(ssz_types::Error),
    MissingBlobs,
    NumBlobsMismatch {
        num_kzg_commitments: usize,
        num_blobs: usize,
    },
    TxKzgCommitmentMismatch,
    KzgCommitmentMismatch {
        blob_index: u64,
    },
    Pending,
    IncorrectFork,
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

/// This cache contains
///  - blobs that have been gossip verified
///  - commitments for blocks that have been gossip verified, but the commitments themselves
///    have not been verified against blobs
///  - blocks that have been fully verified and only require a data availability check
pub struct DataAvailabilityChecker<T: EthSpec, S: SlotClock> {
    availability_cache: RwLock<HashMap<Hash256, ReceivedComponents<T>>>,
    slot_clock: S,
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
pub enum Availability<T: EthSpec> {
    MissingParts(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

impl<T: EthSpec, S: SlotClock> DataAvailabilityChecker<T, S> {
    pub fn new(slot_clock: S, kzg: Option<Arc<Kzg>>, spec: ChainSpec) -> Self {
        Self {
            availability_cache: <_>::default(),
            slot_clock,
            kzg,
            spec,
        }
    }

    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.availability_cache
            .read()
            .get(block_root)
            .map_or(false, |cache| cache.executed_block.is_some())
    }

    pub fn get_missing_blob_ids(&self, block_root: &Hash256) -> Vec<BlobIdentifier> {
        let epoch = self.slot_clock.now().map(|s| s.epoch(T::slots_per_epoch()));
        if epoch.map_or(false, |e| self.da_check_required(e)) {
            self.availability_cache
                .read()
                .get(block_root)
                .map_or(vec![], |cache| {
                    if let Some(block) = cache.executed_block.as_ref() {
                        block.get_filtered_blob_ids(|i, _| cache.verified_blobs.get(i).is_none())
                    } else {
                        let mut blob_ids = Vec::with_capacity(T::max_blobs_per_block());
                        for i in 0..T::max_blobs_per_block() {
                            blob_ids.push(BlobIdentifier {
                                block_root: *block_root,
                                index: i as u64,
                            });
                        }
                        blob_ids
                    }
                })
        } else {
            vec![]
        }
    }

    pub fn wrap_block(
        &self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T>>,
        blobs: FixedVector<Option<Arc<BlobSidecar<T>>>, T::MaxBlobsPerBlock>,
    ) -> Result<BlockWrapper<T>, AvailabilityCheckError> {
        Ok(match self.get_blob_requirements(&block)? {
            BlobRequirements::EmptyBlobs => BlockWrapper::Block(block),
            BlobRequirements::NotRequired => BlockWrapper::Block(block),
            BlobRequirements::PreDeneb => BlockWrapper::Block(block),
            BlobRequirements::Required => {
                let expected_num_blobs = block
                    .message()
                    .body()
                    .blob_kzg_commitments()
                    .map(|commitments| commitments.len())
                    .unwrap_or(0);

                let mut blob_count = 0;
                while let Some((index, Some(blob))) = blobs.iter().enumerate().next() {
                    blob_count += 1;
                    if blob.block_root != block_root {
                        return Err(AvailabilityCheckError::BlockBlobRootMismatch {
                            block_root,
                            blob_block_root: blob.block_root,
                        });
                    }

                    let expected_index = index as u64;
                    if expected_index != blob.index {
                        return Err(AvailabilityCheckError::UnorderedBlobs {
                            expected_index,
                            blob_index: blob.index,
                        });
                    }
                }

                if blob_count < expected_num_blobs {
                    return Err(AvailabilityCheckError::MissingBlobs);
                }

                BlockWrapper::BlockAndBlobs(block, blobs)
            }
        })
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(&self, blob_id: &BlobIdentifier) -> Option<Arc<BlobSidecar<T>>> {
        self.availability_cache
            .read()
            .get(&blob_id.block_root)?
            .verified_blobs
            .get(blob_id.index as usize)?
            .as_ref()
            .map(|kzg_verified_blob| kzg_verified_blob.clone_blob())
    }

    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedVector<Option<Arc<BlobSidecar<T>>>, T::MaxBlobsPerBlock>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        // TODO(sean) we may duplicated kzg verification on some blobs we already have cached so we could optimize this

        let mut verified_blobs = vec![];
        if let Some(kzg) = self.kzg.as_ref() {
            for blob_opt in blobs.into_iter() {
                if let Some(blob) = blob_opt {
                    verified_blobs.push(verify_kzg_for_blob(blob.clone(), kzg)?)
                }
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
        gossip_blob: GossipVerifiedBlob<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        // Verify the KZG commitments.
        let kzg_verified_blob = if let Some(kzg) = self.kzg.as_ref() {
            verify_kzg_for_blob(gossip_blob.to_blob(), kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

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
                    Availability::MissingParts(block_root)
                }
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(ReceivedComponents::new_from_blobs(kzg_verified_blobs));
                Availability::MissingParts(block_root)
            }
        };

        Ok(availability)
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let availability = match self
            .availability_cache
            .write()
            .entry(executed_block.import_data.block_root)
        {
            Entry::Occupied(occupied_entry) => {
                self.check_block_availability_maybe_cache(occupied_entry, executed_block)?
            }
            Entry::Vacant(vacant_entry) => {
                let block_root = executed_block.import_data.block_root;
                vacant_entry.insert(ReceivedComponents::new_from_block(executed_block));
                Availability::MissingParts(block_root)
            }
        };

        Ok(availability)
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
                .map(|maybe_blob| maybe_blob.ok_or(AvailabilityCheckError::MissingBlobs))
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

            Ok(Availability::MissingParts(block_root))
        }
    }

    /// Checks if a block is available, returns a `MaybeAvailableBlock` that may include the fully
    /// available block.
    pub fn check_availability(
        &self,
        block: BlockWrapper<T>,
    ) -> Result<MaybeAvailableBlock<T>, AvailabilityCheckError> {
        match block {
            BlockWrapper::Block(block) => self.check_availability_without_blobs(block),
            BlockWrapper::BlockAndBlobs(block, blob_list) => {
                let kzg = self
                    .kzg
                    .as_ref()
                    .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
                let filtered_blobs = blob_list
                    .to_vec()
                    .into_iter()
                    .filter_map(|blob| blob)
                    .collect();
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
        block: BlockWrapper<T>,
    ) -> Result<AvailableBlock<T>, AvailabilityCheckError> {
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
        block: Arc<SignedBeaconBlock<T>>,
        blobs: KzgVerifiedBlobList<T>,
    ) -> Result<AvailableBlock<T>, AvailabilityCheckError> {
        match self.check_availability_without_blobs(block)? {
            MaybeAvailableBlock::Available(block) => Ok(block),
            MaybeAvailableBlock::AvailabilityPending(pending_block) => {
                self.make_available(pending_block, blobs)
            }
        }
    }

    /// Verifies a block as much as possible, returning a MaybeAvailableBlock enum that may include
    /// an AvailableBlock if no blobs are required. Otherwise this will return an AvailabilityPendingBlock.
    pub fn check_availability_without_blobs(
        &self,
        block: Arc<SignedBeaconBlock<T>>,
    ) -> Result<MaybeAvailableBlock<T>, AvailabilityCheckError> {
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

    /// Verifies an AvailabilityPendingBlock against a set of KZG verified blobs.
    /// This does not check whether a block *should* have blobs, these checks should must have been
    /// completed when producing the `AvailabilityPendingBlock`.
    pub fn make_available(
        &self,
        block: AvailabilityPendingBlock<T>,
        blobs: Vec<KzgVerifiedBlob<T>>,
    ) -> Result<AvailableBlock<T>, AvailabilityCheckError> {
        let block_kzg_commitments = block.kzg_commitments()?;
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
            block: block.block,
            blobs: VerifiedBlobs::Available(blobs),
        })
    }

    /// Determines the blob requirements for a block. Answers the question: "Does this block require
    /// blobs?".
    fn get_blob_requirements(
        &self,
        block: &Arc<SignedBeaconBlock<T, FullPayload<T>>>,
    ) -> Result<BlobRequirements, AvailabilityCheckError> {
        let verified_blobs = if let (Ok(block_kzg_commitments), Ok(payload)) = (
            block.message().body().blob_kzg_commitments(),
            block.message().body().execution_payload(),
        ) {
            if let Some(transactions) = payload.transactions() {
                let verified = verify_kzg_commitments_against_transactions::<T>(
                    transactions,
                    block_kzg_commitments,
                )
                .map_err(|_| AvailabilityCheckError::TxKzgCommitmentMismatch)?;
                if !verified {
                    return Err(AvailabilityCheckError::TxKzgCommitmentMismatch);
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
                .map(|slot| slot.epoch(T::slots_per_epoch()))
                .map(|current_epoch| {
                    std::cmp::max(
                        fork_epoch,
                        current_epoch.saturating_sub(*MIN_EPOCHS_FOR_BLOBS_SIDECARS_REQUESTS),
                    )
                })
        })
    }

    /// Returns true if the given epoch lies within the da boundary and false otherwise.
    pub fn da_check_required(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .map_or(false, |da_epoch| block_epoch >= da_epoch)
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
        self.kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }

    pub fn get_all_blob_ids(&self, block_root: Option<Hash256>) -> Vec<BlobIdentifier> {
        self.get_filtered_blob_ids(block_root, |_, _| true)
    }

    pub fn get_filtered_blob_ids(
        &self,
        block_root: Option<Hash256>,
        filter: impl Fn(usize, Hash256) -> bool,
    ) -> Vec<BlobIdentifier> {
        let block_root = block_root.unwrap_or_else(|| self.as_block().canonical_root());
        let num_blobs_expected = self.num_blobs_expected();
        let mut blob_ids = Vec::with_capacity(num_blobs_expected);
        for i in 0..num_blobs_expected {
            if filter(i, block_root) {
                blob_ids.push(BlobIdentifier {
                    block_root,
                    index: i as u64,
                });
            }
        }
        blob_ids
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
            let blobs_vec = blobs
                .to_vec()
                .into_iter()
                .map(Option::Some)
                .collect::<Vec<_>>();
            BlockWrapper::BlockAndBlobs(block, FixedVector::from(blobs_vec))
        } else {
            BlockWrapper::Block(block)
        }
    }
}
