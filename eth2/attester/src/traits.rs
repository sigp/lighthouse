use types::{AttestationData, Signature};

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
        slot: u64,
        shard: u64,
    ) -> Result<Option<AttestationData>, BeaconNodeError>;

    fn publish_attestation_data(
        &self,
        attestation_data: AttestationData,
        signature: Signature,
        validator_index: u64,
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
    fn attestation_shard(&self, slot: u64) -> Result<Option<u64>, DutiesReaderError>;

    /// Returns `Some(shard)` if this slot is an attestation slot. Otherwise, returns `None.`
    fn validator_index(&self) -> Option<u64>;
}

/// Signs message using an internally-maintained private key.
pub trait Signer {
    fn bls_sign(&self, message: &[u8]) -> Option<Signature>;
}
