//! Provides verification for `PayloadAttestationMessage` received from the gossip network.
//!
//! ```ignore
//!      types::PayloadAttestationMessage
//!              |
//!              ▼
//!      VerifiedPayloadAttestationMessage
//! ```

use crate::BeaconChainError;
use strum::AsRefStr;
use types::{BeaconStateError, Hash256, Slot};

pub mod gossip_verified_payload_attestation;

pub use gossip_verified_payload_attestation::{
    GossipVerificationContext, VerifiedPayloadAttestationMessage,
};

/// Returned when a payload attestation message was not successfully verified. It might not have
/// been verified for two reasons:
///
/// - The message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The payload attestation message is from a slot that is later than the current slot
    /// (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The payload attestation message is from a slot that is prior to the earliest
    /// permissible slot (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// We have already observed a valid payload attestation message from this validator
    /// for this slot.
    ///
    /// ## Peer scoring
    ///
    /// The peer is not necessarily faulty.
    PriorPayloadAttestationMessageKnown { validator_index: u64, slot: Slot },
    /// The beacon block referenced by the payload attestation message is not known.
    ///
    /// ## Peer scoring
    ///
    /// The attestation points to a block we have not yet imported. It's unclear if the
    /// attestation is valid or not.
    UnknownHeadBlock { beacon_block_root: Hash256 },
    /// The validator index is not a member of the PTC for this slot.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    NotInPTC { validator_index: u64, slot: Slot },
    /// The validator index is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    UnknownValidatorIndex(u64),
    /// The signature on the payload attestation message is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSignature,
    /// There was an error whilst processing the payload attestation message. It is not known
    /// if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this message due to an internal error. It's unclear if the
    /// message is valid.
    BeaconChainError(Box<BeaconChainError>),
    /// An error reading beacon state.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this message due to an internal error.
    BeaconStateError(BeaconStateError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

#[cfg(test)]
mod tests;
