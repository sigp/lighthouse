use slot_clock::SlotClock;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::{kzg_utils, BeaconChainError};
use state_processing::per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions;
use types::{BeaconStateError, BlobsSidecar, Hash256, KzgCommitment, Slot, Transactions};

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
    BlobOutOfRange {
        blob_index: usize,
    },

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

    /// No kzg ccommitment associated with blob sidecar.
    KzgCommitmentMissing,

    /// No transactions in block
    TransactionsMissing,

    /// Blob transactions in the block do not correspond to the kzg commitments.
    TransactionCommitmentMismatch,

    TrustedSetupNotInitialized,

    InvalidKzgProof,

    KzgError(kzg::Error),

    /// A blob sidecar for this proposer and slot has already been observed.
    ///
    /// ## Peer scoring
    ///
    /// The `proposer` has already proposed a sidecar at this slot. The existing sidecar may or may not
    /// be equal to the given sidecar.
    RepeatSidecar {
        proposer: u64,
        slot: Slot,
    },

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
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T::EthSpec>,
    block_slot: Slot,
    block_root: Hash256,
    chain: &BeaconChain<T>,
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

    // Verify that kzg commitments in the block are valid BLS g1 points
    for commitment in kzg_commitments {
        if kzg::bytes_to_g1(&commitment.0).is_err() {
            return Err(BlobError::InvalidKZGCommitment);
        }
    }

    // Validate commitments agains transactions in the block.
    if verify_kzg_commitments_against_transactions::<T::EthSpec>(transactions, kzg_commitments)
        .is_err()
    {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Check that blobs are < BLS_MODULUS
    // TODO(pawan): Add this check after there's some resolution of this
    // issue https://github.com/ethereum/c-kzg-4844/issues/11
    // As of now, `bytes_to_bls_field` does not fail in the c-kzg library if blob >= BLS_MODULUS

    // Validate that kzg proof is a valid g1 point
    if kzg::bytes_to_g1(&blob_sidecar.kzg_aggregated_proof.0).is_err() {
        return Err(BlobError::InvalidKzgProof);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    let kzg = chain
        .kzg
        .as_ref()
        .ok_or(BlobError::TrustedSetupNotInitialized)?;

    if !kzg_utils::validate_blobs_sidecar(
        kzg,
        block_slot,
        block_root,
        kzg_commitments,
        blob_sidecar,
    )
    .map_err(BlobError::KzgError)?
    {
        return Err(BlobError::InvalidKzgProof);
    }
    Ok(())
}
