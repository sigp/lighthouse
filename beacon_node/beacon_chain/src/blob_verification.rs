use derivative::Derivative;
use slot_clock::SlotClock;
use state_processing::state_advance::partial_state_advance;
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
use eth2::types::BlockContentsTuple;
use kzg::Kzg;
use slog::{debug, warn};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use std::borrow::Cow;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{
    BeaconBlockRef, BeaconState, BeaconStateError, BlobSidecar, ChainSpec, CloneConfig, Epoch,
    EthSpec, FullPayload, Hash256, KzgCommitment, RelativeEpoch, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedBlobSidecar, Slot,
};

#[derive(Debug)]
pub enum BlobError<T: EthSpec> {
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

    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),

    /// The `BlobSidecar` was gossiped over an incorrect subnet.
    ///
    /// ## Peer scoring
    ///
    /// The blob is invalid or the peer is faulty.
    InvalidSubnet { expected: u64, received: u64 },

    /// The sidecar corresponds to a slot older than the finalized head slot.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this blob is valid, but this blob is for a finalized slot and is
    /// therefore useless to us.
    PastFinalizedSlot {
        blob_slot: Slot,
        finalized_slot: Slot,
    },

    /// The proposer index specified in the sidecar does not match the locally computed
    /// proposer index.
    ///
    /// ## Peer scoring
    ///
    /// The blob is invalid and the peer is faulty.
    ProposerIndexMismatch { sidecar: usize, local: usize },

    /// The proposal signature in invalid.
    ///
    /// ## Peer scoring
    ///
    /// The blob is invalid and the peer is faulty.
    ProposerSignatureInvalid,

    /// The proposal_index corresponding to blob.beacon_block_root is not known.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    UnknownValidator(u64),

    /// The provided blob is not from a later slot than its parent.
    ///
    /// ## Peer scoring
    ///
    /// The blob is invalid and the peer is faulty.
    BlobIsNotLaterThanParent { blob_slot: Slot, parent_slot: Slot },

    /// The provided blob's parent block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// We cannot process the blob without validating its parent, the peer isn't necessarily faulty.
    BlobParentUnknown(Arc<BlobSidecar<T>>),

    /// A blob has already been seen for the given `(sidecar.block_root, sidecar.index)` tuple
    /// over gossip or no gossip sources.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, but we do not forward it over gossip.
    RepeatBlob {
        proposer: u64,
        slot: Slot,
        index: u64,
    },
}

impl<T: EthSpec> From<BeaconChainError> for BlobError<T> {
    fn from(e: BeaconChainError) -> Self {
        BlobError::BeaconChainError(e)
    }
}

impl<T: EthSpec> From<BeaconStateError> for BlobError<T> {
    fn from(e: BeaconStateError) -> Self {
        BlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

/// A wrapper around a `BlobSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug, Clone)]
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
    pub fn slot(&self) -> Slot {
        self.blob.slot
    }
}

pub fn validate_blob_sidecar_for_gossip<T: BeaconChainTypes>(
    signed_blob_sidecar: SignedBlobSidecar<T::EthSpec>,
    subnet: u64,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedBlob<T::EthSpec>, BlobError<T::EthSpec>> {
    let blob_slot = signed_blob_sidecar.message.slot;
    let blob_index = signed_blob_sidecar.message.index;
    let block_parent_root = signed_blob_sidecar.message.block_parent_root;
    let blob_proposer_index = signed_blob_sidecar.message.proposer_index;
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

    // Verify that this is the first blob sidecar received for the (sidecar.block_root, sidecar.index) tuple
    if chain
        .observed_blob_sidecars
        .read()
        .is_known(&signed_blob_sidecar.message)
        .map_err(|e| BlobError::BeaconChainError(e.into()))?
    {
        return Err(BlobError::RepeatBlob {
            proposer: blob_proposer_index,
            slot: blob_slot,
            index: blob_index,
        });
    }

    // We have already verified that the blob is past finalization, so we can
    // just check fork choice for the block's parent.
    if let Some(parent_block) = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&block_parent_root)
    {
        if parent_block.slot >= blob_slot {
            return Err(BlobError::BlobIsNotLaterThanParent {
                blob_slot,
                parent_slot: parent_block.slot,
            });
        }
    } else {
        return Err(BlobError::BlobParentUnknown(signed_blob_sidecar.message));
    }

    // Note: We check that the proposer_index matches against the shuffling first to avoid
    // signature verification against an invalid proposer_index.
    let proposer_shuffling_root = signed_blob_sidecar.message.block_parent_root;

    let proposer_opt = chain
        .beacon_proposer_cache
        .lock()
        .get_slot::<T::EthSpec>(proposer_shuffling_root, blob_slot);

    let (proposer_index, fork) = if let Some(proposer) = proposer_opt {
        (proposer.index, proposer.fork)
    } else {
        debug!(
            chain.log,
            "Proposer shuffling cache miss for blob verification";
            "block_root" => %block_root,
            "index" => %blob_index,
        );
        // The cached head state is in the same epoch as the blob or the state has already been
        // advanced to the blob's epoch
        let snapshot = &chain.canonical_head.cached_head().snapshot;
        if snapshot.beacon_state.current_epoch() == blob_slot.epoch(T::EthSpec::slots_per_epoch()) {
            (
                snapshot
                    .beacon_state
                    .get_beacon_proposer_index(blob_slot, &chain.spec)?,
                snapshot.beacon_state.fork(),
            )
        }
        // Need to advance the state to get the proposer index
        else {
            // Reaching this condition too often might be an issue since we could theoretically have
            // 5 threads (4 blob indices + 1 block) cloning the state.
            // We shouldn't be seeing this condition a lot because we try to advance the state
            // 3 seconds before the start of a slot. However, if this becomes an issue during testing, we should
            // consider sending a blob for reprocessing to reduce the number of state clones.
            warn!(
                chain.log,
                "Cached head not advanced for blob verification";
                "block_root" => %block_root,
                "index" => %blob_index,
                "action" => "contact the devs if you see this msg too often"
            );
            // The state produced is only valid for determining proposer/attester shuffling indices.
            let mut cloned_state = snapshot.clone_with(CloneConfig::committee_caches_only());
            let state = cheap_state_advance_to_obtain_committees(
                &mut cloned_state.beacon_state,
                None,
                blob_slot,
                &chain.spec,
            )?;

            let proposers = state.get_beacon_proposer_indices(&chain.spec)?;
            let proposer_index = *proposers
                .get(blob_slot.as_usize() % T::EthSpec::slots_per_epoch() as usize)
                .ok_or_else(|| BeaconChainError::NoProposerForSlot(blob_slot))?;

            // Prime the proposer shuffling cache with the newly-learned value.
            chain.beacon_proposer_cache.lock().insert(
                blob_slot.epoch(T::EthSpec::slots_per_epoch()),
                proposer_shuffling_root,
                proposers,
                state.fork(),
            )?;
            (proposer_index, state.fork())
        }
    };

    if proposer_index != blob_proposer_index as usize {
        return Err(BlobError::ProposerIndexMismatch {
            sidecar: blob_proposer_index as usize,
            local: proposer_index,
        });
    }

    // Signature verification
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

    // Now the signature is valid, store the proposal so we don't accept another blob sidecar
    // with the same `BlobIdentifier`.
    // It's important to double-check that the proposer still hasn't been observed so we don't
    // have a race-condition when verifying two blocks simultaneously.
    //
    // Note: If this BlobSidecar goes on to fail full verification, we do not evict it from the seen_cache
    // as alternate blob_sidecars for the same identifier can still be retrieved
    // over rpc. Evicting them from this cache would allow faster propagation over gossip. So we allow
    // retreieval of potentially valid blocks over rpc, but try to punish the proposer for signing
    // invalid messages. Issue for more background
    // https://github.com/ethereum/consensus-specs/issues/3261
    if chain
        .observed_blob_sidecars
        .write()
        .observe_sidecar(&signed_blob_sidecar.message)
        .map_err(|e| BlobError::BeaconChainError(e.into()))?
    {
        return Err(BlobError::RepeatBlob {
            proposer: proposer_index as u64,
            slot: blob_slot,
            index: blob_index,
        });
    }

    Ok(GossipVerifiedBlob {
        blob: signed_blob_sidecar.message,
    })
}

/// Performs a cheap (time-efficient) state advancement so the committees and proposer shuffling for
/// `slot` can be obtained from `state`.
///
/// The state advancement is "cheap" since it does not generate state roots. As a result, the
/// returned state might be holistically invalid but the committees/proposers will be correct (since
/// they do not rely upon state roots).
///
/// If the given `state` can already serve the `slot`, the committees will be built on the `state`
/// and `Cow::Borrowed(state)` will be returned. Otherwise, the state will be cloned, cheaply
/// advanced and then returned as a `Cow::Owned`. The end result is that the given `state` is never
/// mutated to be invalid (in fact, it is never changed beyond a simple committee cache build).
///
/// Note: This is a copy of the `block_verification::cheap_state_advance_to_obtain_committees` to return
/// a BlobError error type instead.
/// TODO(pawan): try to unify the 2 functions.
fn cheap_state_advance_to_obtain_committees<'a, E: EthSpec>(
    state: &'a mut BeaconState<E>,
    state_root_opt: Option<Hash256>,
    blob_slot: Slot,
    spec: &ChainSpec,
) -> Result<Cow<'a, BeaconState<E>>, BlobError<E>> {
    let block_epoch = blob_slot.epoch(E::slots_per_epoch());

    if state.current_epoch() == block_epoch {
        // Build both the current and previous epoch caches, as the previous epoch caches are
        // useful for verifying attestations in blocks from the current epoch.
        state.build_committee_cache(RelativeEpoch::Previous, spec)?;
        state.build_committee_cache(RelativeEpoch::Current, spec)?;

        Ok(Cow::Borrowed(state))
    } else if state.slot() > blob_slot {
        Err(BlobError::BlobIsNotLaterThanParent {
            blob_slot,
            parent_slot: state.slot(),
        })
    } else {
        let mut state = state.clone_with(CloneConfig::committee_caches_only());
        let target_slot = block_epoch.start_slot(E::slots_per_epoch());

        // Advance the state into the same epoch as the block. Use the "partial" method since state
        // roots are not important for proposer/attester shuffling.
        partial_state_advance(&mut state, state_root_opt, target_slot, spec)
            .map_err(|e| BlobError::BeaconChainError(BeaconChainError::from(e)))?;

        state.build_committee_cache(RelativeEpoch::Previous, spec)?;
        state.build_committee_cache(RelativeEpoch::Current, spec)?;

        Ok(Cow::Owned(state))
    }
}

/// Wrapper over a `BlobSidecar` for which we have completed kzg verification.
/// i.e. `verify_blob_kzg_proof(blob, commitment, proof) == true`.
#[derive(Debug, Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
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
    let _timer = crate::metrics::start_timer(&crate::metrics::KZG_VERIFICATION_SINGLE_TIMES);
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
    blob_list: Vec<Arc<BlobSidecar<T>>>,
    kzg: &Kzg,
) -> Result<KzgVerifiedBlobList<T>, AvailabilityCheckError> {
    let _timer = crate::metrics::start_timer(&crate::metrics::KZG_VERIFICATION_BATCH_TIMES);
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
    BlockAndBlobs(Arc<SignedBeaconBlock<E>>, FixedBlobSidecarList<E>),
}

impl<E: EthSpec> BlockWrapper<E> {
    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<FixedBlobSidecarList<E>>) {
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

impl<E: EthSpec> BlockWrapper<E> {
    pub fn n_blobs(&self) -> usize {
        match self {
            BlockWrapper::Block(_) => 0,
            BlockWrapper::BlockAndBlobs(_, blobs) => blobs.len(),
        }
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

impl<E: EthSpec> From<BlockContentsTuple<E, FullPayload<E>>> for BlockWrapper<E> {
    fn from(value: BlockContentsTuple<E, FullPayload<E>>) -> Self {
        match value.1 {
            Some(variable_list) => {
                let mut blobs = Vec::with_capacity(E::max_blobs_per_block());
                for blob in variable_list {
                    if blob.message.index < E::max_blobs_per_block() as u64 {
                        blobs.insert(blob.message.index as usize, Some(blob.message));
                    }
                }
                Self::BlockAndBlobs(Arc::new(value.0), FixedVector::from(blobs))
            }
            None => Self::Block(Arc::new(value.0)),
        }
    }
}
