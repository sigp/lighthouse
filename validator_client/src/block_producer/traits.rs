use types::BeaconBlock;

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

/// Defines the methods required to produce and publish blocks on a Beacon Node.
pub trait BeaconNode: Send + Sync {
    /// Request that the node produces a block.
    ///
    /// Returns Ok(None) if the Beacon Node is unable to produce at the given slot.
    fn produce_beacon_block(&self, slot: u64) -> Result<Option<BeaconBlock>, BeaconNodeError>;
    /// Request that the node publishes a block.
    ///
    /// Returns `true` if the publish was sucessful.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconNodeError>;
}
