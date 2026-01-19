use crate::kzg_utils::{validate_blob, validate_blobs};
use crate::{BeaconChainError, metrics};
use educe::Educe;
use kzg::{Error as KzgError, Kzg, KzgCommitment};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use tree_hash::TreeHash;
use types::{BeaconStateError, BlobSidecar, EthSpec, Hash256, Slot};

/// An error occurred while validating a gossip blob.
#[derive(Debug)]
pub enum GossipBlobError {
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
    BeaconChainError(Box<BeaconChainError>),

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
    ParentUnknown { parent_root: Hash256 },

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

    /// The kzg verification failed.
    ///
    /// ## Peer scoring
    ///
    /// The blob sidecar is invalid and the peer is faulty.
    KzgError(kzg::Error),

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

impl std::fmt::Display for GossipBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconChainError> for GossipBlobError {
    fn from(e: BeaconChainError) -> Self {
        GossipBlobError::BeaconChainError(e.into())
    }
}

impl From<BeaconStateError> for GossipBlobError {
    fn from(e: BeaconStateError) -> Self {
        GossipBlobError::BeaconChainError(BeaconChainError::BeaconStateError(e).into())
    }
}

/// Wrapper over a `BlobSidecar` for which we have completed kzg verification.
/// i.e. `verify_blob_kzg_proof(blob, commitment, proof) == true`.
#[derive(Debug, Educe, Clone, Encode, Decode)]
#[educe(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedBlob<E: EthSpec> {
    blob: Arc<BlobSidecar<E>>,
    #[ssz(skip_serializing, skip_deserializing)]
    seen_timestamp: Duration,
}

impl<E: EthSpec> PartialOrd for KzgVerifiedBlob<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EthSpec> Ord for KzgVerifiedBlob<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.blob.cmp(&other.blob)
    }
}

impl<E: EthSpec> KzgVerifiedBlob<E> {
    pub fn new(
        blob: Arc<BlobSidecar<E>>,
        kzg: &Kzg,
        seen_timestamp: Duration,
    ) -> Result<Self, KzgError> {
        verify_kzg_for_blob(blob, kzg, seen_timestamp)
    }
    pub fn to_blob(self) -> Arc<BlobSidecar<E>> {
        self.blob
    }
    pub fn as_blob(&self) -> &BlobSidecar<E> {
        &self.blob
    }
    pub fn get_commitment(&self) -> &KzgCommitment {
        &self.blob.kzg_commitment
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_blob(&self) -> Arc<BlobSidecar<E>> {
        self.blob.clone()
    }
    pub fn blob_index(&self) -> u64 {
        self.blob.index
    }
    pub fn seen_timestamp(&self) -> Duration {
        self.seen_timestamp
    }
    /// Construct a `KzgVerifiedBlob` that is assumed to be valid.
    ///
    /// This should ONLY be used for testing.
    #[cfg(test)]
    pub fn __assumed_valid(blob: Arc<BlobSidecar<E>>) -> Self {
        Self {
            blob,
            seen_timestamp: Duration::from_secs(0),
        }
    }
    /// Mark a blob as KZG verified. Caller must ONLY use this on blob sidecars constructed
    /// from EL blobs.
    pub fn from_execution_verified(blob: Arc<BlobSidecar<E>>, seen_timestamp: Duration) -> Self {
        Self {
            blob,
            seen_timestamp,
        }
    }
}

/// Complete kzg verification for a `BlobSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_blob<E: EthSpec>(
    blob: Arc<BlobSidecar<E>>,
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedBlob<E>, KzgError> {
    validate_blob::<E>(kzg, &blob.blob, blob.kzg_commitment, blob.kzg_proof)?;
    Ok(KzgVerifiedBlob {
        blob,
        seen_timestamp,
    })
}

pub struct KzgVerifiedBlobList<E: EthSpec> {
    verified_blobs: Vec<KzgVerifiedBlob<E>>,
}

impl<E: EthSpec> KzgVerifiedBlobList<E> {
    pub fn new<I: IntoIterator<Item = Arc<BlobSidecar<E>>>>(
        blob_list: I,
        kzg: &Kzg,
        seen_timestamp: Duration,
    ) -> Result<Self, KzgError> {
        let blobs = blob_list
            .into_iter()
            .map(|blob| KzgVerifiedBlob {
                blob,
                seen_timestamp,
            })
            .collect::<Vec<_>>();
        verify_kzg_for_blob_list(blobs.iter().map(|b| &b.blob), kzg)?;
        Ok(Self {
            verified_blobs: blobs,
        })
    }

    /// Create a `KzgVerifiedBlobList` from `blobs` that are already KZG verified.
    pub fn from_verified<I: IntoIterator<Item = KzgVerifiedBlob<E>>>(blobs: I) -> Self {
        Self {
            verified_blobs: blobs.into_iter().collect(),
        }
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
#[instrument(skip_all, level = "debug")]
pub fn verify_kzg_for_blob_list<'a, E: EthSpec, I>(
    blob_iter: I,
    kzg: &'a Kzg,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<BlobSidecar<E>>>,
{
    let (blobs, (commitments, proofs)): (Vec<_>, (Vec<_>, Vec<_>)) = blob_iter
        .map(|blob| (&blob.blob, (blob.kzg_commitment, blob.kzg_proof)))
        .unzip();
    validate_blobs::<E>(kzg, commitments.as_slice(), blobs, proofs.as_slice())
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
