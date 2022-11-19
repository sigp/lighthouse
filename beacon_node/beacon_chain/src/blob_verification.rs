use derivative::Derivative;
use slot_clock::SlotClock;
use std::sync::Arc;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::BeaconChainError;
use bls::PublicKey;
use types::{consts::eip4844::BLS_MODULUS, BeaconStateError, BlobsSidecar, Hash256, Slot};

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
    /// The blob sidecar is from a slot that is prior to the earliest permissible slot (with
    /// respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },

    /// The blob sidecar contains an incorrectly formatted `BLSFieldElement` > `BLS_MODULUS`.
    ///
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    BlobOutOfRange { blob_index: usize },

    /// The blob sidecar contains a KZGCommitment that is not a valid G1 point on
    /// the bls curve.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidKZGCommitment,
    /// The proposal signature in invalid.
    ///
    /// ## Peer scoring
    ///
    /// The signature on the blob sidecar invalid and the peer is faulty.
    ProposalSignatureInvalid,

    /// A blob sidecar for this proposer and slot has already been observed.
    ///
    /// ## Peer scoring
    ///
    /// The `proposer` has already proposed a sidecar at this slot. The existing sidecar may or may not
    /// be equal to the given sidecar.
    RepeatSidecar { proposer: u64, slot: Slot },

    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),
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

pub fn validate_blob_for_gossip<T: BeaconChainTypes>(
    blob_sidecar: &BlobsSidecar<T::EthSpec>,
    chain: &Arc<BeaconChain<T>>,
) -> Result<(), BlobError> {
    let blob_slot = blob_sidecar.beacon_block_slot;
    // Do not gossip or process blobs from future or past slots.
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if blob_slot > latest_permissible_slot {
        return Err(BlobError::FutureSlot {
            message_slot: latest_permissible_slot,
            latest_permissible_slot: blob_slot,
        });
    }

    let earliest_permissible_slot = chain
        .slot_clock
        .now_with_past_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if blob_slot > earliest_permissible_slot {
        return Err(BlobError::PastSlot {
            message_slot: earliest_permissible_slot,
            earliest_permissible_slot: blob_slot,
        });
    }

    // Verify that blobs are properly formatted
    //TODO: add the check while constructing a Blob type from bytes instead of after
    for (i, blob) in blob_sidecar.blobs.iter().enumerate() {
        if blob.iter().any(|b| *b >= *BLS_MODULUS) {
            return Err(BlobError::BlobOutOfRange { blob_index: i });
        }
    }

    // Verify that the KZG proof is a valid G1 point
    if PublicKey::deserialize(&blob_sidecar.kzg_aggregate_proof.0).is_err() {
        return Err(BlobError::InvalidKZGCommitment);
    }

    // TODO: `validate_blobs_sidecar`
    Ok(())
}
