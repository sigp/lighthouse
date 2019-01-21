use super::EpochDuties;
use bls::PublicKey;

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
}

pub trait BeaconNode: Send + Sync {
    fn request_shuffling(
        &self,
        epoch: u64,
        public_key: &PublicKey,
    ) -> Result<Option<EpochDuties>, BeaconNodeError>;
}
