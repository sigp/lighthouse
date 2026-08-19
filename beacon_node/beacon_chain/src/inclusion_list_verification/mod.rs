use crate::BeaconChainError;
use std::sync::Arc;
use types::{BeaconStateError, Slot};

pub mod gossip_verified_inclusion_list;

#[derive(Debug)]
pub enum InclusionListVerificationError {
    /// Two valid inclusion lists were already seen from this validator for this slot.
    AlreadySeenTwice { validator_index: u64, slot: Slot },
    /// The slot clock cannot read.
    UnableToReadSlot,
    /// Beacon Chain error
    BeaconChainError(Arc<BeaconChainError>),
    /// Beacon State error
    BeaconStateError(BeaconStateError),
}

impl std::fmt::Display for InclusionListVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconChainError> for InclusionListVerificationError {
    fn from(e: BeaconChainError) -> Self {
        InclusionListVerificationError::BeaconChainError(Arc::new(e))
    }
}

impl From<BeaconStateError> for InclusionListVerificationError {
    fn from(e: BeaconStateError) -> Self {
        InclusionListVerificationError::BeaconStateError(e)
    }
}
