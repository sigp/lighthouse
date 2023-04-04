use derivative::Derivative;
use slot_clock::SlotClock;
use std::sync::Arc;

use crate::beacon_chain::{
    BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
    VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
};
use crate::data_availability_checker::{
    AvailabilityCheckError, AvailabilityPendingBlock, AvailableBlock,
};
use crate::kzg_utils::{validate_blob, validate_blobs};
use crate::BeaconChainError;
use kzg::Kzg;
use types::blob_sidecar::BlobIdentifier;
use types::{
    BeaconBlockRef, BeaconStateError, BlobSidecar, BlobSidecarList, Epoch, EthSpec, Hash256,
    KzgCommitment, SignedBeaconBlock, SignedBeaconBlockHeader, SignedBlobSidecar, Slot,
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
    /// Blobs provided for a pre-Deneb fork.
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
    pub fn id(&self) -> BlobIdentifier {
        self.blob.id()
    }
    pub fn block_root(&self) -> Hash256 {
        self.blob.block_root
    }
    pub fn to_blob(self) -> Arc<BlobSidecar<T>> {
        self.blob
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

/// Wrapper over a `BlobSidecar` for which we have completed kzg verification.
/// i.e. `verify_blob_kzg_proof(blob, commitment, proof) == true`.
#[derive(Debug, Derivative, Clone)]
#[derivative(PartialEq, Eq)]
pub struct KzgVerifiedBlob<T: EthSpec> {
    blob: Arc<BlobSidecar<T>>,
}

impl<T: EthSpec> PartialOrd for KzgVerifiedBlob<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.blob.partial_cmp(&other.blob)
    }
}

impl<T: EthSpec> Ord for KzgVerifiedBlob<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.blob.cmp(&other.blob)
    }
}

impl<T: EthSpec> KzgVerifiedBlob<T> {
    pub fn to_blob(self) -> Arc<BlobSidecar<T>> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar<T> {
        &self.blob
    }
    pub fn clone_blob(&self) -> Arc<BlobSidecar<T>> {
        self.blob.clone()
    }
    pub fn kzg_commitment(&self) -> KzgCommitment {
        self.blob.kzg_commitment
    }
    pub fn block_root(&self) -> Hash256 {
        self.blob.block_root
    }
    pub fn blob_index(&self) -> u64 {
        self.blob.index
    }
}

/// Complete kzg verification for a `GossipVerifiedBlob`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_blob<T: EthSpec>(
    blob: Arc<BlobSidecar<T>>,
    kzg: &Kzg,
) -> Result<KzgVerifiedBlob<T>, AvailabilityCheckError> {
    //TODO(sean) remove clone
    if validate_blob::<T>(kzg, blob.blob.clone(), blob.kzg_commitment, blob.kzg_proof)
        .map_err(AvailabilityCheckError::Kzg)?
    {
        Ok(KzgVerifiedBlob { blob })
    } else {
        Err(AvailabilityCheckError::KzgVerificationFailed)
    }
}

/// Complete kzg verification for a list of `BlobSidecar`s.
/// Returns an error if any of the `BlobSidecar`s fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_blob`
/// in a loop since this function kzg verifies a list of blobs more efficiently.
pub fn verify_kzg_for_blob_list<T: EthSpec>(
    blob_list: BlobSidecarList<T>,
    kzg: &Kzg,
) -> Result<KzgVerifiedBlobList<T>, AvailabilityCheckError> {
    let (blobs, (commitments, proofs)): (Vec<_>, (Vec<_>, Vec<_>)) = blob_list
        .clone()
        .into_iter()
        //TODO(sean) remove clone
        .map(|blob| (blob.blob.clone(), (blob.kzg_commitment, blob.kzg_proof)))
        .unzip();
    if validate_blobs::<T>(
        kzg,
        commitments.as_slice(),
        blobs.as_slice(),
        proofs.as_slice(),
    )
    .map_err(AvailabilityCheckError::Kzg)?
    {
        Ok(blob_list
            .into_iter()
            .map(|blob| KzgVerifiedBlob { blob })
            .collect())
    } else {
        Err(AvailabilityCheckError::KzgVerificationFailed)
    }
}

pub type KzgVerifiedBlobList<T> = Vec<KzgVerifiedBlob<T>>;

#[derive(Debug, Clone)]
pub enum MaybeAvailableBlock<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-deneb blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending(AvailabilityPendingBlock<E>),
}

/// Trait for common block operations.
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

impl<E: EthSpec> AsBlock<E> for MaybeAvailableBlock<E> {
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
            MaybeAvailableBlock::Available(block) => block.as_block(),
            MaybeAvailableBlock::AvailabilityPending(block) => block.as_block(),
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.block_cloned(),
            MaybeAvailableBlock::AvailabilityPending(block) => block.block_cloned(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        match self {
            MaybeAvailableBlock::Available(available_block) => available_block.into_block_wrapper(),
            MaybeAvailableBlock::AvailabilityPending(pending_block) => {
                BlockWrapper::Block(pending_block.to_block())
            }
        }
    }
}

impl<E: EthSpec> AsBlock<E> for &MaybeAvailableBlock<E> {
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
            MaybeAvailableBlock::Available(block) => block.as_block(),
            MaybeAvailableBlock::AvailabilityPending(block) => block.as_block(),
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.block_cloned(),
            MaybeAvailableBlock::AvailabilityPending(block) => block.block_cloned(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self.clone().into_block_wrapper()
    }
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub enum BlockWrapper<E: EthSpec> {
    Block(Arc<SignedBeaconBlock<E>>),
    BlockAndBlobs(Arc<SignedBeaconBlock<E>>, Vec<Arc<BlobSidecar<E>>>),
}

impl<E: EthSpec> BlockWrapper<E> {
    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<Vec<Arc<BlobSidecar<E>>>>) {
        match self {
            BlockWrapper::Block(block) => (block, None),
            BlockWrapper::BlockAndBlobs(block, blobs) => (block, Some(blobs)),
        }
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
            BlockWrapper::Block(block) => block,
            BlockWrapper::BlockAndBlobs(block, _) => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlobs(block, _) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self
    }
}

impl<E: EthSpec> From<Arc<SignedBeaconBlock<E>>> for BlockWrapper<E> {
    fn from(value: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::Block(value)
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for BlockWrapper<E> {
    fn from(value: SignedBeaconBlock<E>) -> Self {
        Self::Block(Arc::new(value))
    }
}
