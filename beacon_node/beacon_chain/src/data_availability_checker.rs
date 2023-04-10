use crate::blob_verification::{
    verify_kzg_for_blob, verify_kzg_for_blob_list, AsBlock, BlockWrapper, GossipVerifiedBlob,
    KzgVerifiedBlob, KzgVerifiedBlobList, MaybeAvailableBlock,
};
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};

use crate::data_availability_checker::overflow_lru_cache::OverflowLRUCache;
use crate::{BeaconChainTypes, BeaconStore};
use kzg::Error as KzgError;
use kzg::Kzg;
use slot_clock::SlotClock;
use ssz_types::{Error, VariableList};
use state_processing::per_block_processing::deneb::deneb::verify_kzg_commitments_against_transactions;
use std::sync::Arc;
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::consts::deneb::MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS;
use types::ssz_tagged_signed_beacon_block;
use types::{
    BeaconBlockRef, BlobSidecarList, ChainSpec, Epoch, EthSpec, ExecPayload, FullPayload, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

mod overflow_lru_cache;

pub const OVERFLOW_LRU_CAPACITY: usize = 64;

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
    BlobIndexInvalid(u64),
    StoreError(store::Error),
    DecodeError(ssz::DecodeError),
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
    availability_cache: OverflowLRUCache<T>,
    slot_clock: T::SlotClock,
    kzg: Option<Arc<Kzg>>,
    spec: ChainSpec,
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
pub enum Availability<T: EthSpec> {
    PendingBlobs(Vec<BlobIdentifier>),
    PendingBlock(Hash256),
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
    ) -> Self {
        Self {
            availability_cache: OverflowLRUCache::new(OVERFLOW_LRU_CAPACITY, store),
            slot_clock,
            kzg,
            spec,
        }
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_blob(blob_id)
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
            verify_kzg_for_blob(gossip_blob, kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        Ok(self
            .availability_cache
            .put_kzg_verified_blob(kzg_verified_blob)?)
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
                let verified_blobs = verify_kzg_for_blob_list(VariableList::new(blob_list)?, kzg)?;

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
            BlockWrapper::BlockAndBlobs(block, blobs.to_vec())
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
    use super::*;

    #[test]
    fn check_encode_decode_availability_pending_block() {
        // todo.. (difficult to create default beacon blocks to test)
    }
}