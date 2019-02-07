use types::{AttestationData, FreeAttestation, Signature, Slot};

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PublishOutcome {
    ValidAttestation,
    InvalidAttestation(String),
}

/// Defines the methods required to produce and publish blocks on a Beacon Node.
pub trait BeaconNode: Send + Sync {
    fn produce_attestation_data(
        &self,
        slot: Slot,
        shard: u64,
    ) -> Result<Option<AttestationData>, BeaconNodeError>;

    fn publish_attestation_data(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<PublishOutcome, BeaconNodeError>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum DutiesReaderError {
    UnknownValidator,
    UnknownEpoch,
    EpochLengthIsZero,
    Poisoned,
}

/// Informs a validator of their duties (e.g., block production).
pub trait DutiesReader: Send + Sync {
    /// Returns `Some(shard)` if this slot is an attestation slot. Otherwise, returns `None.`
    fn attestation_shard(&self, slot: Slot) -> Result<Option<u64>, DutiesReaderError>;

    /// Returns `Some(shard)` if this slot is an attestation slot. Otherwise, returns `None.`
    fn validator_index(&self) -> Option<u64>;
}

/// Signs message using an internally-maintained private key.
pub trait Signer {
    fn sign_attestation_message(&self, message: &[u8]) -> Option<Signature>;
}
