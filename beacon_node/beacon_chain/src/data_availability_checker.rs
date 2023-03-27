use crate::blob_verification::{
    verify_kzg_for_blob, verify_kzg_for_blob_list, AsBlock, BlockWrapper, GossipVerifiedBlob,
    KzgVerifiedBlob, KzgVerifiedBlobList, MaybeAvailableBlock,
};
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};

use kzg::Error as KzgError;
use kzg::Kzg;
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use ssz_types::{Error, VariableList};
use state_processing::per_block_processing::deneb::deneb::verify_kzg_commitments_against_transactions;
use std::collections::hash_map::Entry;
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
    rpc_blob_cache: RwLock<HashMap<BlobIdentifier, Arc<BlobSidecar<T>>>>,
    gossip_blob_cache: Mutex<HashMap<Hash256, GossipBlobCache<T>>>,
    slot_clock: S,
    kzg: Option<Arc<Kzg>>,
    spec: ChainSpec,
}

struct GossipBlobCache<T: EthSpec> {
    verified_blobs: Vec<KzgVerifiedBlob<T>>,
    executed_block: Option<AvailabilityPendingExecutedBlock<T>>,
}

pub enum Availability<T: EthSpec> {
    PendingBlobs(Vec<BlobIdentifier>),
    PendingBlock(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

impl<T: EthSpec, S: SlotClock> DataAvailabilityChecker<T, S> {
    pub fn new(slot_clock: S, kzg: Option<Arc<Kzg>>, spec: ChainSpec) -> Self {
        Self {
            rpc_blob_cache: <_>::default(),
            gossip_blob_cache: <_>::default(),
            slot_clock,
            kzg,
            spec,
        }
    }

    /// This first validate the KZG commitments included in the blob sidecar.
    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the Availability variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_blob(
        &self,
        verified_blob: GossipVerifiedBlob<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let block_root = verified_blob.block_root();

        let kzg_verified_blob = if let Some(kzg) = self.kzg.as_ref() {
            verify_kzg_for_blob(verified_blob, kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        //TODO(sean) can we just use a referece to the blob here?
        let blob = kzg_verified_blob.clone_blob();

        // check if we have a block
        // check if the complete set matches the block
        // verify, otherwise cache

        let mut blob_cache = self.gossip_blob_cache.lock();

        // Gossip cache.
        let availability = match blob_cache.entry(blob.block_root) {
            Entry::Occupied(mut occupied_entry) => {
                // All blobs reaching this cache should be gossip verified and gossip verification
                // should filter duplicates, as well as validate indices.
                let cache = occupied_entry.get_mut();

                cache
                    .verified_blobs
                    .insert(blob.index as usize, kzg_verified_blob);

                if let Some(executed_block) = cache.executed_block.take() {
                    self.check_block_availability_or_cache(cache, executed_block)?
                } else {
                    Availability::PendingBlock(block_root)
                }
            }
            Entry::Vacant(vacant_entry) => {
                let block_root = kzg_verified_blob.block_root();
                vacant_entry.insert(GossipBlobCache {
                    verified_blobs: vec![kzg_verified_blob],
                    executed_block: None,
                });
                Availability::PendingBlock(block_root)
            }
        };

        drop(blob_cache);

        // RPC cache.
        self.rpc_blob_cache.write().insert(blob.id(), blob.clone());

        Ok(availability)
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let mut guard = self.gossip_blob_cache.lock();
        let entry = guard.entry(executed_block.import_data.block_root);

        let availability = match entry {
            Entry::Occupied(mut occupied_entry) => {
                let cache: &mut GossipBlobCache<T> = occupied_entry.get_mut();

                self.check_block_availability_or_cache(cache, executed_block)?
            }
            Entry::Vacant(vacant_entry) => {
                let kzg_commitments_len = executed_block.block.kzg_commitments()?.len();
                let mut blob_ids = Vec::with_capacity(kzg_commitments_len);
                for i in 0..kzg_commitments_len {
                    blob_ids.push(BlobIdentifier {
                        block_root: executed_block.import_data.block_root,
                        index: i as u64,
                    });
                }

                vacant_entry.insert(GossipBlobCache {
                    verified_blobs: vec![],
                    executed_block: Some(executed_block),
                });

                Availability::PendingBlobs(blob_ids)
            }
        };

        Ok(availability)
    }

    fn check_block_availability_or_cache(
        &self,
        cache: &mut GossipBlobCache<T>,
        executed_block: AvailabilityPendingExecutedBlock<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = executed_block;
        let kzg_commitments_len = block.kzg_commitments()?.len();
        let verified_commitments_len = cache.verified_blobs.len();
        if kzg_commitments_len == verified_commitments_len {
            //TODO(sean) can we remove this clone
            let blobs = cache.verified_blobs.clone();
            let available_block = self.make_available(block, blobs)?;
            Ok(Availability::Available(Box::new(
                AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ),
            )))
        } else {
            let mut missing_blobs = Vec::with_capacity(kzg_commitments_len);
            for i in 0..kzg_commitments_len {
                if cache.verified_blobs.get(i).is_none() {
                    missing_blobs.push(BlobIdentifier {
                        block_root: import_data.block_root,
                        index: i as u64,
                    })
                }
            }

            let _ = cache
                .executed_block
                .insert(AvailabilityPendingExecutedBlock::new(
                    block,
                    import_data,
                    payload_verification_outcome,
                ));

            Ok(Availability::PendingBlobs(missing_blobs))
        }
    }

    /// Checks if a block is available, returns a MaybeAvailableBlock enum that may include the fully
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
    /// completed when producing the AvailabilityPendingBlock.
    pub fn make_available(
        &self,
        block: AvailabilityPendingBlock<T>,
        blobs: KzgVerifiedBlobList<T>,
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
}

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
