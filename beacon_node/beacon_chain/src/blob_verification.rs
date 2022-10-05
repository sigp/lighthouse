use derivative::Derivative;
use slot_clock::SlotClock;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::{block_verification::get_validator_pubkey_cache, BeaconChainError};
use bls::PublicKey;
use std::sync::Arc;
use types::{
    consts::eip4844::BLS_MODULUS, BeaconStateError, BlobsSidecar, EthSpec, Hash256,
    SignedBlobsSidecar, Slot,
};

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

    /// The `blobs_sidecar.message.beacon_block_root` block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The attestation points to a block we have not yet imported. It's unclear if the attestation
    /// is valid or not.
    UnknownHeadBlock { beacon_block_root: Hash256 },

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

/// A wrapper around a `SignedBlobsSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Derivative)]
#[derivative(Debug(bound = "T: BeaconChainTypes"))]
pub struct VerifiedBlobsSidecar<'a, T: BeaconChainTypes> {
    pub blob_sidecar: &'a SignedBlobsSidecar<T::EthSpec>,
}

impl<'a, T: BeaconChainTypes> VerifiedBlobsSidecar<'a, T> {
    pub fn verify(
        blob_sidecar: &'a SignedBlobsSidecar<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlobError> {
        let blob_slot = blob_sidecar.message.beacon_block_slot;
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
        for (i, blob) in blob_sidecar.message.blobs.iter().enumerate() {
            if blob.iter().any(|b| *b >= *BLS_MODULUS) {
                return Err(BlobError::BlobOutOfRange { blob_index: i });
            }
        }

        // Verify that the KZG proof is a valid G1 point
        if PublicKey::deserialize(&blob_sidecar.message.kzg_aggregate_proof.0).is_err() {
            return Err(BlobError::InvalidKZGCommitment);
        }

        // TODO: Verify proposer signature

        // // let state = /* Get a valid state */
        // let proposer_index = state.get_beacon_proposer_index(blob_slot, &chain.spec)? as u64;
        // let signature_is_valid = {
        //     let pubkey_cache = get_validator_pubkey_cache(chain)?;
        //     let pubkey = pubkey_cache
        //         .get(proposer_index as usize)
        //         .ok_or_else(|| BlobError::UnknownValidator(proposer_index)?;
        //     blob.verify_signature(
        //         Some(block_root),
        //         pubkey,
        //         &fork,
        //         chain.genesis_validators_root,
        //         &chain.spec,
        //     )
        // };

        // if !signature_is_valid {
        //     return Err(BlobError::ProposalSignatureInvalid);
        // }

        // TODO: Check that we have not already received a sidecar with a valid signature for this slot.

        Ok(Self { blob_sidecar })
    }
}
