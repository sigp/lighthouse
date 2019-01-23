use super::traits::{BeaconNode, BeaconNodeError};
use std::sync::RwLock;
use types::BeaconBlock;

type ProduceResult = Result<Option<BeaconBlock>, BeaconNodeError>;
type PublishResult = Result<bool, BeaconNodeError>;

/// A test-only struct used to simulate a Beacon Node.
#[derive(Default)]
pub struct TestBeaconNode {
    pub produce_input: RwLock<Option<u64>>,
    pub produce_result: RwLock<Option<ProduceResult>>,
    pub publish_input: RwLock<Option<BeaconBlock>>,
    pub publish_result: RwLock<Option<PublishResult>>,
}

impl TestBeaconNode {
    /// Set the result to be returned when `produce_beacon_block` is called.
    pub fn set_next_produce_result(&self, result: ProduceResult) {
        *self.produce_result.write().unwrap() = Some(result);
    }

    /// Set the result to be returned when `publish_beacon_block` is called.
    pub fn set_next_publish_result(&self, result: PublishResult) {
        *self.publish_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for TestBeaconNode {
    /// Returns the value specified by the `set_next_produce_result`.
    fn produce_beacon_block(&self, slot: u64) -> ProduceResult {
        *self.produce_input.write().unwrap() = Some(slot);
        match *self.produce_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: produce_result == None"),
        }
    }

    /// Returns the value specified by the `set_next_publish_result`.
    fn publish_beacon_block(&self, block: BeaconBlock) -> PublishResult {
        *self.publish_input.write().unwrap() = Some(block);
        match *self.publish_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: publish_result == None"),
        }
    }
}
