use types::{BeaconBlock, PublicKey, Signature};

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

/// Defines the methods required to produce and publish blocks on a Beacon Node.
pub trait BeaconNode: Send + Sync {
    /// Requests the proposer nonce (presently named `proposer_slots`).
    fn proposer_nonce(&self, pubkey: &PublicKey) -> Result<u64, BeaconNodeError>;

    /// Request that the node produces a block.
    ///
    /// Returns Ok(None) if the Beacon Node is unable to produce at the given slot.
    fn produce_beacon_block(
        &self,
        slot: u64,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconNodeError>;

    /// Request that the node publishes a block.
    ///
    /// Returns `true` if the publish was sucessful.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconNodeError>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum DutiesReaderError {
    UnknownValidator,
    UnknownEpoch,
    Poisoned,
}

/// Informs a validator of their duties (e.g., block production).
pub trait DutiesReader: Send + Sync {
    fn is_block_production_slot(&self, epoch: u64, slot: u64) -> Result<bool, DutiesReaderError>;
}

/// Signs message using an internally-maintained private key.
pub trait Signer {
    fn bls_sign(&self, message: &[u8]) -> Option<Signature>;
}
