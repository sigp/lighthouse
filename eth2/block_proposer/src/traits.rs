use types::{BeaconBlock, Fork, Signature, Slot};

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PublishOutcome {
    ValidBlock,
    InvalidBlock(String),
}

/// Defines the methods required to produce and publish blocks on a Beacon Node.
pub trait BeaconNode: Send + Sync {
    /// Request that the node produces a block.
    ///
    /// Returns Ok(None) if the Beacon Node is unable to produce at the given slot.
    fn produce_beacon_block(
        &self,
        slot: Slot,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconNodeError>;

    /// Request that the node publishes a block.
    ///
    /// Returns `true` if the publish was sucessful.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<PublishOutcome, BeaconNodeError>;
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
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, DutiesReaderError>;
    fn fork(&self) -> Result<Fork, DutiesReaderError>;
}

/// Signs message using an internally-maintained private key.
pub trait Signer {
    fn sign_block_proposal(&self, message: &[u8], domain: u64) -> Option<Signature>;
    fn sign_randao_reveal(&self, message: &[u8], domain: u64) -> Option<Signature>;
}
