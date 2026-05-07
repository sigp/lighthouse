//! Gossip verification for proposer preferences.
//!
//! A `SignedProposerPreferences` is verified and wrapped as a `GossipVerifiedProposerPreferences`,
//! which is then inserted into the `GossipVerifiedProposerPreferenceCache`.
//!
//! ```ignore
//!    SignedProposerPreferences
//!              |
//!              ▼
//!    GossipVerifiedProposerPreferences -------> Insert into GossipVerifiedProposerPreferenceCache
//! ```

use std::sync::Arc;

use types::{BeaconStateError, Epoch, Slot};

use crate::BeaconChainError;

pub mod gossip_verified_proposer_preferences;
pub mod proposer_preference_cache;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum ProposerPreferencesError {
    /// The proposal slot is not in the current or next epoch.
    InvalidProposalEpoch { proposal_epoch: Epoch },
    /// The proposal slot has already passed.
    ProposalSlotAlreadyPassed {
        proposal_slot: Slot,
        current_slot: Slot,
    },
    /// The validator index does not match the proposer at the given slot.
    InvalidProposalSlot {
        validator_index: u64,
        proposal_slot: Slot,
    },
    /// The slot clock cannot be read.
    UnableToReadSlot,
    /// A valid message from this validator for this slot has already been seen.
    AlreadySeen {
        validator_index: u64,
        proposal_slot: Slot,
    },
    /// The signature is invalid.
    BadSignature,
    /// Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    /// Some Beacon State error
    BeaconStateError(BeaconStateError),
}

impl std::fmt::Display for ProposerPreferencesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconStateError> for ProposerPreferencesError {
    fn from(e: BeaconStateError) -> Self {
        ProposerPreferencesError::BeaconStateError(e)
    }
}

impl From<BeaconChainError> for ProposerPreferencesError {
    fn from(e: BeaconChainError) -> Self {
        ProposerPreferencesError::BeaconChainError(Arc::new(e))
    }
}
