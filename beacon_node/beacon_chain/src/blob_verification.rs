use derivative::Derivative;
use slot_clock::SlotClock;
use std::sync::Arc;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT};
use crate::block_verification::{
    cheap_state_advance_to_obtain_committees, get_validator_pubkey_cache, process_block_slash_info,
    BlockSlashInfo,
};
use crate::kzg_utils::{validate_blob, validate_blobs};
use crate::{metrics, BeaconChainError};
use kzg::{Error as KzgError, Kzg, KzgCommitment};
use merkle_proof::MerkleTreeError;
use slog::{debug, warn};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash::TreeHash;
use types::blob_sidecar::BlobIdentifier;
use types::{
    BeaconStateError, BlobSidecar, CloneConfig, EthSpec, Hash256, SignedBeaconBlockHeader, Slot,
};

/// An error occurred while validating a gossip blob.
#[derive(Debug)]
pub enum GossipBlobError<T: EthSpec> {
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

    /// There was an error whilst processing the blob. It is not known if it is
    /// valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this blob due to an internal error. It's
    /// unclear if the blob is valid.
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
    ProposalSignatureInvalid,

    /// The proposal_index corresponding to blob.beacon_block_root is not known.
    ///
    /// ## Peer scoring
    ///
    /// The blob is invalid and the peer is faulty.
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

    /// Invalid kzg commitment inclusion proof
    /// ## Peer scoring
    ///
    /// The blob sidecar is invalid and the peer is faulty
    InvalidInclusionProof,

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

    /// `Kzg` struct hasn't been initialized. This is an internal error.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, This is an internal error.
    KzgNotInitialized,

    /// The kzg verification failed.
    ///
    /// ## Peer scoring
    ///
    /// The blob sidecar is invalid and the peer is faulty.
    KzgError(kzg::Error),

    /// The kzg commitment inclusion proof failed.
    ///
    /// ## Peer scoring
    ///
    /// The blob sidecar is invalid
    InclusionProof(MerkleTreeError),

    /// The pubkey cache timed out.
    ///
    /// ## Peer scoring
    ///
    /// The blob sidecar may be valid, this is an internal error.
    PubkeyCacheTimeout,

    /// The block conflicts with finalization, no need to propagate.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this block is valid, but it conflicts with finality and shouldn't be
    /// imported.
    NotFinalizedDescendant { block_parent_root: Hash256 },
}

impl<T: EthSpec> std::fmt::Display for GossipBlobError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipBlobError::BlobParentUnknown(blob_sidecar) => {
                write!(
                    f,
                    "BlobParentUnknown(parent_root:{})",
                    blob_sidecar.block_parent_root()
                )
            }
            other => write!(f, "{:?}", other),
        }
    }
}

impl<T: EthSpec> From<BeaconChainError> for GossipBlobError<T> {
    fn from(e: BeaconChainError) -> Self {
        GossipBlobError::BeaconChainError(e)
    }
}

impl<T: EthSpec> From<BeaconStateError> for GossipBlobError<T> {
    fn from(e: BeaconStateError) -> Self {
        GossipBlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

pub type GossipVerifiedBlobList<T> = VariableList<
    GossipVerifiedBlob<T>,
    <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
>;

/// A wrapper around a `BlobSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug)]
pub struct GossipVerifiedBlob<T: BeaconChainTypes> {
    block_root: Hash256,
    blob: KzgVerifiedBlob<T::EthSpec>,
}

impl<T: BeaconChainTypes> GossipVerifiedBlob<T> {
    pub fn new(
        blob: Arc<BlobSidecar<T::EthSpec>>,
        subnet_id: u64,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipBlobError<T::EthSpec>> {
        let header = blob.signed_block_header.clone();
        // We only process slashing info if the gossip verification failed
        // since we do not process the blob any further in that case.
        validate_blob_sidecar_for_gossip(blob, subnet_id, chain).map_err(|e| {
            process_block_slash_info::<_, GossipBlobError<T::EthSpec>>(
                chain,
                BlockSlashInfo::from_early_error_blob(header, e),
            )
        })
    }
    /// Construct a `GossipVerifiedBlob` that is assumed to be valid.
    ///
    /// This should ONLY be used for testing.
    pub fn __assumed_valid(blob: Arc<BlobSidecar<T::EthSpec>>) -> Self {
        Self {
            block_root: blob.block_root(),
            blob: KzgVerifiedBlob { blob },
        }
    }
    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root,
            index: self.blob.blob_index(),
        }
    }
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }
    pub fn slot(&self) -> Slot {
        self.blob.blob.slot()
    }
    pub fn index(&self) -> u64 {
        self.blob.blob.index
    }
    pub fn kzg_commitment(&self) -> KzgCommitment {
        self.blob.blob.kzg_commitment
    }
    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.blob.blob.signed_block_header.clone()
    }
    pub fn block_proposer_index(&self) -> u64 {
        self.blob.blob.block_proposer_index()
    }
    pub fn into_inner(self) -> KzgVerifiedBlob<T::EthSpec> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar<T::EthSpec> {
        self.blob.as_blob()
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_blob(&self) -> Arc<BlobSidecar<T::EthSpec>> {
        self.blob.clone_blob()
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
        Some(self.cmp(other))
    }
}

impl<T: EthSpec> Ord for KzgVerifiedBlob<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.blob.cmp(&other.blob)
    }
}

impl<T: EthSpec> KzgVerifiedBlob<T> {
    pub fn new(blob: Arc<BlobSidecar<T>>, kzg: &Kzg) -> Result<Self, KzgError> {
        verify_kzg_for_blob(blob, kzg)
    }
    pub fn to_blob(self) -> Arc<BlobSidecar<T>> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar<T> {
        &self.blob
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_blob(&self) -> Arc<BlobSidecar<T>> {
        self.blob.clone()
    }
    pub fn blob_index(&self) -> u64 {
        self.blob.index
    }
    /// Construct a `KzgVerifiedBlob` that is assumed to be valid.
    ///
    /// This should ONLY be used for testing.
    #[cfg(test)]
    pub fn __assumed_valid(blob: Arc<BlobSidecar<T>>) -> Self {
        Self { blob }
    }
}

/// Complete kzg verification for a `BlobSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_blob<T: EthSpec>(
    blob: Arc<BlobSidecar<T>>,
    kzg: &Kzg,
) -> Result<KzgVerifiedBlob<T>, KzgError> {
    validate_blob::<T>(kzg, &blob.blob, blob.kzg_commitment, blob.kzg_proof)?;
    Ok(KzgVerifiedBlob { blob })
}

pub struct KzgVerifiedBlobList<E: EthSpec> {
    verified_blobs: Vec<KzgVerifiedBlob<E>>,
}

impl<E: EthSpec> KzgVerifiedBlobList<E> {
    pub fn new<I: IntoIterator<Item = Arc<BlobSidecar<E>>>>(
        blob_list: I,
        kzg: &Kzg,
    ) -> Result<Self, KzgError> {
        let blobs = blob_list.into_iter().collect::<Vec<_>>();
        verify_kzg_for_blob_list(blobs.iter(), kzg)?;
        Ok(Self {
            verified_blobs: blobs
                .into_iter()
                .map(|blob| KzgVerifiedBlob { blob })
                .collect(),
        })
    }
}

impl<E: EthSpec> IntoIterator for KzgVerifiedBlobList<E> {
    type Item = KzgVerifiedBlob<E>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.verified_blobs.into_iter()
    }
}

/// Complete kzg verification for a list of `BlobSidecar`s.
/// Returns an error if any of the `BlobSidecar`s fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_blob`
/// in a loop since this function kzg verifies a list of blobs more efficiently.
pub fn verify_kzg_for_blob_list<'a, T: EthSpec, I>(
    blob_iter: I,
    kzg: &'a Kzg,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<BlobSidecar<T>>>,
{
    let (blobs, (commitments, proofs)): (Vec<_>, (Vec<_>, Vec<_>)) = blob_iter
        .map(|blob| (&blob.blob, (blob.kzg_commitment, blob.kzg_proof)))
        .unzip();
    validate_blobs::<T>(kzg, commitments.as_slice(), blobs, proofs.as_slice())
}

pub fn validate_blob_sidecar_for_gossip<T: BeaconChainTypes>(
    blob_sidecar: Arc<BlobSidecar<T::EthSpec>>,
    subnet: u64,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedBlob<T>, GossipBlobError<T::EthSpec>> {
    let blob_slot = blob_sidecar.slot();
    let blob_index = blob_sidecar.index;
    let block_parent_root = blob_sidecar.block_parent_root();
    let blob_proposer_index = blob_sidecar.block_proposer_index();
    let block_root = blob_sidecar.block_root();
    let blob_epoch = blob_slot.epoch(T::EthSpec::slots_per_epoch());
    let signed_block_header = &blob_sidecar.signed_block_header;

    // This condition is not possible if we have received the blob from the network
    // since we only subscribe to `MaxBlobsPerBlock` subnets over gossip network.
    // We include this check only for completeness.
    // Getting this error would imply something very wrong with our networking decoding logic.
    if blob_index >= T::EthSpec::max_blobs_per_block() as u64 {
        return Err(GossipBlobError::InvalidSubnet {
            expected: subnet,
            received: blob_index,
        });
    }

    // Verify that the blob_sidecar was received on the correct subnet.
    if blob_index != subnet {
        return Err(GossipBlobError::InvalidSubnet {
            expected: blob_index,
            received: subnet,
        });
    }

    // Verify that the sidecar is not from a future slot.
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(chain.spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if blob_slot > latest_permissible_slot {
        return Err(GossipBlobError::FutureSlot {
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
        return Err(GossipBlobError::PastFinalizedSlot {
            blob_slot,
            finalized_slot: latest_finalized_slot,
        });
    }

    // Verify that this is the first blob sidecar received for the tuple:
    // (block_header.slot, block_header.proposer_index, blob_sidecar.index)
    if chain
        .observed_blob_sidecars
        .read()
        .proposer_is_known(&blob_sidecar)
        .map_err(|e| GossipBlobError::BeaconChainError(e.into()))?
    {
        return Err(GossipBlobError::RepeatBlob {
            proposer: blob_proposer_index,
            slot: blob_slot,
            index: blob_index,
        });
    }

    // Verify the inclusion proof in the sidecar
    let _timer = metrics::start_timer(&metrics::BLOB_SIDECAR_INCLUSION_PROOF_VERIFICATION);
    if !blob_sidecar
        .verify_blob_sidecar_inclusion_proof()
        .map_err(GossipBlobError::InclusionProof)?
    {
        return Err(GossipBlobError::InvalidInclusionProof);
    }
    drop(_timer);

    let fork_choice = chain.canonical_head.fork_choice_read_lock();

    // We have already verified that the blob is past finalization, so we can
    // just check fork choice for the block's parent.
    let Some(parent_block) = fork_choice.get_block(&block_parent_root) else {
        return Err(GossipBlobError::BlobParentUnknown(blob_sidecar));
    };

    // Do not process a blob that does not descend from the finalized root.
    // We just loaded the parent_block, so we can be sure that it exists in fork choice.
    if !fork_choice.is_finalized_checkpoint_or_descendant(block_parent_root) {
        return Err(GossipBlobError::NotFinalizedDescendant { block_parent_root });
    }
    drop(fork_choice);

    if parent_block.slot >= blob_slot {
        return Err(GossipBlobError::BlobIsNotLaterThanParent {
            blob_slot,
            parent_slot: parent_block.slot,
        });
    }

    let proposer_shuffling_root =
        if parent_block.slot.epoch(T::EthSpec::slots_per_epoch()) == blob_epoch {
            parent_block
                .next_epoch_shuffling_id
                .shuffling_decision_block
        } else {
            parent_block.root
        };

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
        if let Some(mut snapshot) = chain
            .snapshot_cache
            .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|snapshot_cache| {
                snapshot_cache.get_cloned(block_parent_root, CloneConfig::committee_caches_only())
            })
        {
            if snapshot.beacon_state.slot() == blob_slot {
                debug!(
                    chain.log,
                    "Cloning snapshot cache state for blob verification";
                    "block_root" => %block_root,
                    "index" => %blob_index,
                );
                (
                    snapshot
                        .beacon_state
                        .get_beacon_proposer_index(blob_slot, &chain.spec)?,
                    snapshot.beacon_state.fork(),
                )
            } else {
                debug!(
                    chain.log,
                    "Cloning and advancing snapshot cache state for blob verification";
                    "block_root" => %block_root,
                    "index" => %blob_index,
                );
                let state =
                    cheap_state_advance_to_obtain_committees::<_, GossipBlobError<T::EthSpec>>(
                        &mut snapshot.beacon_state,
                        Some(snapshot.beacon_block_root),
                        blob_slot,
                        &chain.spec,
                    )?;
                (
                    state.get_beacon_proposer_index(blob_slot, &chain.spec)?,
                    state.fork(),
                )
            }
        }
        // Need to advance the state to get the proposer index
        else {
            warn!(
                chain.log,
                "Snapshot cache miss for blob verification";
                "block_root" => %block_root,
                "index" => %blob_index,
            );

            let parent_block = chain
                .get_blinded_block(&block_parent_root)
                .map_err(GossipBlobError::BeaconChainError)?
                .ok_or_else(|| {
                    GossipBlobError::from(BeaconChainError::MissingBeaconBlock(block_parent_root))
                })?;

            let mut parent_state = chain
                .get_state(&parent_block.state_root(), Some(parent_block.slot()))?
                .ok_or_else(|| {
                    BeaconChainError::DBInconsistent(format!(
                        "Missing state {:?}",
                        parent_block.state_root()
                    ))
                })?;
            let state = cheap_state_advance_to_obtain_committees::<_, GossipBlobError<T::EthSpec>>(
                &mut parent_state,
                Some(parent_block.state_root()),
                blob_slot,
                &chain.spec,
            )?;

            let proposers = state.get_beacon_proposer_indices(&chain.spec)?;
            let proposer_index = *proposers
                .get(blob_slot.as_usize() % T::EthSpec::slots_per_epoch() as usize)
                .ok_or_else(|| BeaconChainError::NoProposerForSlot(blob_slot))?;

            let fork = state.fork();
            // Prime the proposer shuffling cache with the newly-learned value.
            chain.beacon_proposer_cache.lock().insert(
                blob_epoch,
                proposer_shuffling_root,
                proposers,
                fork,
            )?;
            (proposer_index, fork)
        }
    };

    // Signature verify the signed block header.
    let signature_is_valid = {
        let pubkey_cache =
            get_validator_pubkey_cache(chain).map_err(|_| GossipBlobError::PubkeyCacheTimeout)?;
        let pubkey = pubkey_cache
            .get(proposer_index)
            .ok_or_else(|| GossipBlobError::UnknownValidator(proposer_index as u64))?;
        signed_block_header.verify_signature::<T::EthSpec>(
            pubkey,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
    };

    if !signature_is_valid {
        return Err(GossipBlobError::ProposalSignatureInvalid);
    }

    if proposer_index != blob_proposer_index as usize {
        return Err(GossipBlobError::ProposerIndexMismatch {
            sidecar: blob_proposer_index as usize,
            local: proposer_index,
        });
    }

    // Now the signature is valid, store the proposal so we don't accept another blob sidecar
    // with the same `BlobIdentifier`.
    // It's important to double-check that the proposer still hasn't been observed so we don't
    // have a race-condition when verifying two blocks simultaneously.
    //
    // Note: If this BlobSidecar goes on to fail full verification, we do not evict it from the seen_cache
    // as alternate blob_sidecars for the same identifier can still be retrieved
    // over rpc. Evicting them from this cache would allow faster propagation over gossip. So we allow
    // retrieval of potentially valid blocks over rpc, but try to punish the proposer for signing
    // invalid messages. Issue for more background
    // https://github.com/ethereum/consensus-specs/issues/3261
    if chain
        .observed_blob_sidecars
        .write()
        .observe_sidecar(&blob_sidecar)
        .map_err(|e| GossipBlobError::BeaconChainError(e.into()))?
    {
        return Err(GossipBlobError::RepeatBlob {
            proposer: proposer_index as u64,
            slot: blob_slot,
            index: blob_index,
        });
    }

    // Kzg verification for gossip blob sidecar
    let kzg = chain
        .kzg
        .as_ref()
        .ok_or(GossipBlobError::KzgNotInitialized)?;
    let kzg_verified_blob =
        KzgVerifiedBlob::new(blob_sidecar, kzg).map_err(GossipBlobError::KzgError)?;

    Ok(GossipVerifiedBlob {
        block_root,
        blob: kzg_verified_blob,
    })
}

/// Returns the canonical root of the given `blob`.
///
/// Use this function to ensure that we report the blob hashing time Prometheus metric.
pub fn get_blob_root<E: EthSpec>(blob: &BlobSidecar<E>) -> Hash256 {
    let blob_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOB_ROOT);

    let blob_root = blob.tree_hash_root();

    metrics::stop_timer(blob_root_timer);

    blob_root
}
