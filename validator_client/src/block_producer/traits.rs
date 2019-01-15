use types::BeaconBlock;

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

pub trait BeaconNode {
    fn produce_beacon_block(&self, slot: u64) -> Result<Option<BeaconBlock>, BeaconNodeError>;
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconNodeError>;
}
