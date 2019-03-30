use super::EpochDuties;
use types::{Epoch, Keypair};

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeDutiesError {
    RemoteFailure(String),
}

/// Defines the methods required to obtain a validators shuffling from a Beacon Node.
pub trait BeaconNodeDuties: Send + Sync {
    /// Gets the duties for all validators.
    ///
    /// Returns a vector of EpochDuties for each validator public key. The entry will be None for
    /// validators that are not activated.
    fn request_duties(
        &self,
        epoch: Epoch,
        signers: &[Keypair],
    ) -> Result<EpochDuties, BeaconNodeDutiesError>;
}
