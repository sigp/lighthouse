use super::EpochDuties;
use crate::error::BeaconNodeError;
use crate::service::BoxFut;
use types::{Epoch, PublicKey};

/// Defines the methods required to obtain a validators shuffling from a Beacon Node.
pub trait BeaconNodeDuties: Send + Sync {
    /// Gets the duties for all validators.
    ///
    /// Returns a vector of EpochDuties for each validator public key. The entry will be None for
    /// validators that are not activated.
    fn request_duties(
        &self,
        epoch: Epoch,
        pub_keys: &[PublicKey],
    ) -> BoxFut<EpochDuties, BeaconNodeError>;
}
