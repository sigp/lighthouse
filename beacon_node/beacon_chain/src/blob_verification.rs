use slot_clock::SlotClock;
use std::sync::Arc;

use crate::beacon_chain::{
    BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
    VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
};
use crate::data_availability_checker::AvailabilityCheckError;
use crate::kzg_utils::validate_blob;
use crate::{kzg_utils, BeaconChainError, BlockProductionError};
use derivative::Derivative;
use kzg::Kzg;
use ssz_types::VariableList;
use state_processing::per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions;
use types::{
    BeaconBlockRef, BeaconStateError, BlobSidecar, BlobSidecarList, Epoch, EthSpec, ExecPayload,
    Hash256, KzgCommitment, SignedBeaconBlock, SignedBeaconBlockHeader, SignedBlobSidecar, Slot,
    Transactions,
};

#[derive(Debug)]
pub enum BlobError {
    /// The blob sidecar is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },

    /// The blob sidecar has a different slot than the block.
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    SlotMismatch {
        blob_slot: Slot,
        block_slot: Slot,
    },

    /// No kzg ccommitment associated with blob sidecar.
    KzgCommitmentMissing,

    /// No transactions in block
    TransactionsMissing,

    /// Blob transactions in the block do not correspond to the kzg commitments.
    TransactionCommitmentMismatch,

    TrustedSetupNotInitialized,

    InvalidKzgProof,

    KzgError(kzg::Error),

    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),
    /// No blobs for the specified block where we would expect blobs.
    UnavailableBlobs,
    /// Blobs provided for a pre-Eip4844 fork.
    InconsistentFork,

    /// The `blobs_sidecar.message.beacon_block_root` block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The blob points to a block we have not yet imported. The blob cannot be imported
    /// into fork choice yet
    UnknownHeadBlock {
        beacon_block_root: Hash256,
    },

    /// The `BlobSidecar` was gossiped over an incorrect subnet.
    InvalidSubnet {
        expected: u64,
        received: u64,
    },

    /// The sidecar corresponds to a slot older than the finalized head slot.
    PastFinalizedSlot {
        blob_slot: Slot,
        finalized_slot: Slot,
    },

    /// The proposer index specified in the sidecar does not match the locally computed
    /// proposer index.
    ProposerIndexMismatch {
        sidecar: usize,
        local: usize,
    },

    ProposerSignatureInvalid,

    /// A sidecar with same slot, beacon_block_root and proposer_index but different blob is received for
    /// the same blob index.
    RepeatSidecar {
        proposer: usize,
        slot: Slot,
        blob_index: usize,
    },

    /// The proposal_index corresponding to blob.beacon_block_root is not known.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    UnknownValidator(u64),

    BlobCacheError(AvailabilityCheckError),
}

impl From<BeaconChainError> for BlobError {
    fn from(e: BeaconChainError) -> Self {
        BlobError::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for BlobError {
    fn from(e: BeaconStateError) -> Self {
        BlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

/// A wrapper around a `BlobSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug)]
pub struct GossipVerifiedBlob<T: EthSpec> {
    blob: Arc<BlobSidecar<T>>,
}

impl<T: EthSpec> GossipVerifiedBlob<T> {
    pub fn block_root(&self) -> Hash256 {
        self.blob.block_root
    }
}

pub fn validate_blob_sidecar_for_gossip<T: BeaconChainTypes>(
    signed_blob_sidecar: SignedBlobSidecar<T::EthSpec>,
    subnet: u64,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedBlob<T::EthSpec>, BlobError> {
    let blob_slot = signed_blob_sidecar.message.slot;
    let blob_index = signed_blob_sidecar.message.index;
    let block_root = signed_blob_sidecar.message.block_root;

    // Verify that the blob_sidecar was received on the correct subnet.
    if blob_index != subnet {
        return Err(BlobError::InvalidSubnet {
            expected: blob_index,
            received: subnet,
        });
    }

    // Verify that the sidecar is not from a future slot.
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if blob_slot > latest_permissible_slot {
        return Err(BlobError::FutureSlot {
            message_slot: blob_slot,
            latest_permissible_slot,
        });
    }

    // TODO(pawan): Verify not from a past slot?

    // Verify that the sidecar slot is greater than the latest finalized slot
    let latest_finalized_slot = chain
        .head()
        .finalized_checkpoint()
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    if blob_slot <= latest_finalized_slot {
        return Err(BlobError::PastFinalizedSlot {
            blob_slot,
            finalized_slot: latest_finalized_slot,
        });
    }

    // TODO(pawan): should we verify locally that the parent root is correct
    // or just use whatever the proposer gives us?
    let proposer_shuffling_root = signed_blob_sidecar.message.block_parent_root;

    let (proposer_index, fork) = match chain
        .beacon_proposer_cache
        .lock()
        .get_slot::<T::EthSpec>(proposer_shuffling_root, blob_slot)
    {
        Some(proposer) => (proposer.index, proposer.fork),
        None => {
            let state = &chain.canonical_head.cached_head().snapshot.beacon_state;
            (
                state.get_beacon_proposer_index(blob_slot, &chain.spec)?,
                state.fork(),
            )
        }
    };

    let blob_proposer_index = signed_blob_sidecar.message.proposer_index;
    if proposer_index != blob_proposer_index as usize {
        return Err(BlobError::ProposerIndexMismatch {
            sidecar: blob_proposer_index as usize,
            local: proposer_index,
        });
    }

    let signature_is_valid = {
        let pubkey_cache = chain
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)
            .map_err(BlobError::BeaconChainError)?;

        let pubkey = pubkey_cache
            .get(proposer_index)
            .ok_or_else(|| BlobError::UnknownValidator(proposer_index as u64))?;

        signed_blob_sidecar.verify_signature(
            None,
            pubkey,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
    };

    if !signature_is_valid {
        return Err(BlobError::ProposerSignatureInvalid);
    }

    // TODO(pawan): kzg validations.

    // TODO(pawan): Check if other blobs for the same proposer index and blob index have been
    // received and drop if required.

    // Verify if the corresponding block for this blob has been received.
    // Note: this should be the last gossip check so that we can forward the blob
    // over the gossip network even if we haven't received the corresponding block yet
    // as all other validations have passed.
    let block_opt = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&block_root)
        .or_else(|| chain.early_attester_cache.get_proto_block(block_root)); // TODO(pawan): should we be checking this cache?

    // TODO(pawan): this may be redundant with the new `AvailabilityProcessingStatus::PendingBlock variant`
    if block_opt.is_none() {
        return Err(BlobError::UnknownHeadBlock {
            beacon_block_root: block_root,
        });
    }

    Ok(GossipVerifiedBlob {
        blob: signed_blob_sidecar.message,
    })
}

#[derive(Debug, Clone)]
pub struct KzgVerifiedBlob<T: EthSpec> {
    blob: Arc<BlobSidecar<T>>,
}

impl<T: EthSpec> KzgVerifiedBlob<T> {
    pub fn clone_blob(&self) -> Arc<BlobSidecar<T>> {
        self.blob.clone()
    }
    pub fn kzg_commitment(&self) -> KzgCommitment {
        self.blob.kzg_commitment
    }
    pub fn block_root(&self) -> Hash256 {
        self.blob.block_root
    }
}

pub fn verify_kzg_for_blob<T: EthSpec>(
    blob: GossipVerifiedBlob<T>,
    kzg: &Kzg,
) -> Result<KzgVerifiedBlob<T>, AvailabilityCheckError> {
    //TODO(sean) remove clone
    if validate_blob::<T>(
        kzg,
        blob.blob.blob.clone(),
        blob.blob.kzg_commitment,
        blob.blob.kzg_proof,
    )
    .map_err(AvailabilityCheckError::Kzg)?
    {
        Ok(KzgVerifiedBlob { blob: blob.blob })
    } else {
        return Err(AvailabilityCheckError::KzgVerificationFailed);
    }
}

pub type KzgVerifiedBlobList<T> = Vec<KzgVerifiedBlob<T>>;

#[derive(Clone, Debug, PartialEq, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub struct AvailableBlock<E: EthSpec>(AvailableBlockInner<E>);

#[derive(Clone, Debug, PartialEq, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
struct AvailableBlockInner<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    blobs: VerifiedBlobs<E>,
}

pub trait IntoKzgVerifiedBlobs<T: EthSpec> {
    fn into_kzg_verified_blobs(
        self,
        kzg: Option<Arc<Kzg>>,
    ) -> Result<KzgVerifiedBlobList<T>, AvailabilityCheckError>;
    fn is_empty(&self) -> bool;
}

impl<T: EthSpec> IntoKzgVerifiedBlobs<T> for KzgVerifiedBlobList<T> {
    fn into_kzg_verified_blobs(
        self,
        kzg: Option<Arc<Kzg>>,
    ) -> Result<KzgVerifiedBlobList<T>, AvailabilityCheckError> {
        Ok(self)
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<E: EthSpec> IntoKzgVerifiedBlobs<E> for Vec<Arc<BlobSidecar<E>>> {
    fn into_kzg_verified_blobs(
        self,
        kzg: Option<Arc<Kzg>>,
    ) -> Result<KzgVerifiedBlobList<E>, AvailabilityCheckError> {
        todo!()
        // verify batch kzg, need this for creating available blocks in
        // `process_chain_segment` or local block production
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn new<Blobs: IntoKzgVerifiedBlobs<E>>(
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Blobs,
        da_check: impl FnOnce(Epoch) -> bool,
        kzg: Option<Arc<Kzg>>,
    ) -> Result<Self, AvailabilityCheckError> {
        if let (Ok(block_kzg_commitments), Ok(payload)) = (
            block.message().body().blob_kzg_commitments(),
            block.message().body().execution_payload(),
        ) {
            if blobs.is_empty() && block_kzg_commitments.is_empty() {
                return Ok(Self(AvailableBlockInner {
                    block,
                    blobs: VerifiedBlobs::EmptyBlobs,
                }));
            }

            if blobs.is_empty() {
                if da_check(block.epoch()) {
                    return Ok(Self(AvailableBlockInner {
                        block,
                        blobs: VerifiedBlobs::NotRequired,
                    }));
                } else {
                    return Err(AvailabilityCheckError::MissingBlobs);
                }
            }

            let blobs = blobs.into_kzg_verified_blobs(kzg)?;

            if blobs.len() != block_kzg_commitments.len() {
                return Err(AvailabilityCheckError::NumBlobsMismatch {
                    num_kzg_commitments: block_kzg_commitments.len(),
                    num_blobs: blobs.len(),
                });
            }

            // If there are no transactions here, this is a blinded block.
            if let Some(transactions) = payload.transactions() {
                verify_kzg_commitments_against_transactions::<E>(
                    transactions,
                    block_kzg_commitments,
                )
                .map_err(|_| AvailabilityCheckError::TxKzgCommitmentMismatch)?;
            }

            for (block_commitment, blob) in block_kzg_commitments.iter().zip(blobs.iter()) {
                if *block_commitment != blob.kzg_commitment() {
                    return Err(AvailabilityCheckError::KzgCommitmentMismatch {
                        blob_index: blob.blob.index,
                    });
                }
            }

            let verified_blobs =
                VariableList::new(blobs.into_iter().map(|blob| blob.blob).collect())?;

            //TODO(sean) AvailableBlockInner not add anything if the fields of AvailableBlock are private
            Ok(Self(AvailableBlockInner {
                block,
                blobs: VerifiedBlobs::Available(verified_blobs),
            }))
        }
        // This is a pre eip4844 block
        else {
            Ok(Self(AvailableBlockInner {
                block,
                blobs: VerifiedBlobs::PreEip4844,
            }))
        }
    }

    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.0.block
    }

    pub fn blobs(&self) -> Option<BlobSidecarList<E>> {
        match &self.0.blobs {
            VerifiedBlobs::EmptyBlobs | VerifiedBlobs::NotRequired | VerifiedBlobs::PreEip4844 => {
                None
            }
            VerifiedBlobs::Available(blobs) => Some(blobs.clone()),
        }
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<BlobSidecarList<E>>) {
        match self.0.blobs {
            VerifiedBlobs::EmptyBlobs | VerifiedBlobs::NotRequired | VerifiedBlobs::PreEip4844 => {
                (self.0.block, None)
            }
            VerifiedBlobs::Available(blobs) => (self.0.block, Some(blobs)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub enum VerifiedBlobs<E: EthSpec> {
    /// These blobs are available.
    //TODO(sean) add AvailableBlobsInner, this shouldn't be mutable
    Available(BlobSidecarList<E>),
    /// This block is from outside the data availability boundary so doesn't require
    /// a data availability check.
    NotRequired,
    /// The block's `kzg_commitments` field is empty so it does not contain any blobs.
    EmptyBlobs,
    /// This is a block prior to the 4844 fork, so doesn't require any blobs
    PreEip4844,
}

pub trait AsBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
    fn canonical_root(&self) -> Hash256;
    fn into_block_wrapper(self) -> BlockWrapper<E>;
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub enum BlockWrapper<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-eip4844 blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending(Arc<SignedBeaconBlock<E>>),
    /// This variant is useful in the networking stack to separate consensus checks from networking.
    AvailabiltyCheckDelayed(Arc<SignedBeaconBlock<E>>, Vec<Arc<BlobSidecar<E>>>),
}

impl<E: EthSpec> BlockWrapper<E> {
    pub fn into_available_block(
        self,
        kzg: Option<Arc<Kzg>>,
        da_check: impl FnOnce(Epoch) -> bool,
    ) -> Result<AvailableBlock<E>, AvailabilityCheckError> {
        match self {
            BlockWrapper::AvailabilityPending(_) => Err(AvailabilityCheckError::Pending),
            BlockWrapper::Available(block) => Ok(block),
            BlockWrapper::AvailabiltyCheckDelayed(block, blobs) => {
                AvailableBlock::new(block, blobs, da_check, kzg)
            }
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.0.block.slot()
    }

    fn epoch(&self) -> Epoch {
        self.0.block.epoch()
    }

    fn parent_root(&self) -> Hash256 {
        self.0.block.parent_root()
    }

    fn state_root(&self) -> Hash256 {
        self.0.block.state_root()
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.0.block.signed_block_header()
    }

    fn message(&self) -> BeaconBlockRef<E> {
        self.0.block.message()
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.0.block
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.0.block.clone()
    }

    fn canonical_root(&self) -> Hash256 {
        self.0.block.canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        BlockWrapper::Available(self)
    }
}

impl<E: EthSpec> AsBlock<E> for BlockWrapper<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Available(block) => &block.0.block,
            BlockWrapper::AvailabilityPending(block) => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Available(block) => block.0.block.clone(),
            BlockWrapper::AvailabilityPending(block) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self
    }
}

impl<E: EthSpec> AsBlock<E> for &BlockWrapper<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Available(block) => &block.0.block,
            BlockWrapper::AvailabilityPending(block) => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Available(block) => block.0.block.clone(),
            BlockWrapper::AvailabilityPending(block) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self.clone()
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for BlockWrapper<E> {
    fn from(block: SignedBeaconBlock<E>) -> Self {
        BlockWrapper::AvailabilityPending(Arc::new(block))
    }
}

impl<E: EthSpec> From<Arc<SignedBeaconBlock<E>>> for BlockWrapper<E> {
    fn from(block: Arc<SignedBeaconBlock<E>>) -> Self {
        BlockWrapper::AvailabilityPending(block)
    }
}

impl<E: EthSpec> From<AvailableBlock<E>> for BlockWrapper<E> {
    fn from(block: AvailableBlock<E>) -> Self {
        BlockWrapper::Available(block)
    }
}
