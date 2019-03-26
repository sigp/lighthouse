use super::EpochDuties;
use types::{Epoch, PublicKey};

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
}

/// Defines the methods required to obtain a validators shuffling from a Beacon Node.
pub trait BeaconNode: Send + Sync {
    /// Get the shuffling for the given epoch and public key.
    ///
    /// Returns Ok(None) if the public key is unknown, or the shuffling for that epoch is unknown.
    fn request_shuffling(
        &self,
        epoch: Epoch,
        pubkeys: &[PublicKey],
    ) -> Result<Option<EpochDuties>, BeaconNodeError>;
}
