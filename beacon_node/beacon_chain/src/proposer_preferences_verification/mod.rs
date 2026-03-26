//! The incremental processing steps are represented as a sequence of wrapper-types around the preferences.
//! There is a linear progression of types, starting at a `SignedProposerPreferences` and finishing
//! with a `GossipVerifiedProposerPreferences` which is then inserted into the `GossipVerifiedProposerPreferenceCache`
//!
//! ```ignore
//!    SignedProposerPreferences
//!              |
//!              ▼
//!    SignatureVerifiedProposerPreferences -------> Insert into GossipVerifiedProposerPreferenceCache::seen
//!              |
//!              ▼
//!    GossipVerifiedProposerPreferences -------> Insert into GossipVerifiedProposerPreferenceCache::preferences
//! ```

use std::sync::Arc;

use types::{BeaconStateError, Slot};

use crate::BeaconChainError;

pub mod gossip_verified_proposer_preferences;
pub mod proposer_preference_cache;

#[derive(Debug)]
pub enum ProposerPreferencesError {
    /// The proposal slot is not in the current or next epoch.
    InvalidProposalSlotEpoch { proposal_slot: Slot },
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
