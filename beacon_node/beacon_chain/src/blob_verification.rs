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
    BeaconStateError, BlobSidecar, CloneConfig, DataColumnSidecar, EthSpec, Hash256,
    SignedBeaconBlockHeader, Slot,
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

#[derive(Debug)]
pub struct GossipVerifiedDataColumnSidecar<T: BeaconChainTypes> {
    data_column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
}

impl<T: BeaconChainTypes> GossipVerifiedDataColumnSidecar<T> {
    pub fn new(
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        subnet_id: u64,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipBlobError<T::EthSpec>> {
        let header = column_sidecar.signed_block_header.clone();
        // We only process slashing info if the gossip verification failed
        // since we do not process the blob any further in that case.
        validate_data_column_sidecar_for_gossip(column_sidecar, subnet_id, chain).map_err(|e| {
            process_block_slash_info::<_, GossipBlobError<T::EthSpec>>(
                chain,
                BlockSlashInfo::from_early_error_blob(header, e),
            )
        })
    }

    pub fn as_data_column(&self) -> &Arc<DataColumnSidecar<T::EthSpec>> {
        &self.data_column_sidecar
    }
}

pub fn validate_data_column_sidecar_for_gossip<T: BeaconChainTypes>(
    data_column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
    _subnet: u64,
    _chain: &BeaconChain<T>,
) -> Result<GossipVerifiedDataColumnSidecar<T>, GossipBlobError<T::EthSpec>> {
    // TODO(das): validate kzg commitments, cell proofs etc
    Ok(GossipVerifiedDataColumnSidecar {
        data_column_sidecar: data_column_sidecar.clone(),
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
