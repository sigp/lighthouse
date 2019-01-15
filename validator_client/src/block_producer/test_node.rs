use super::traits::{BeaconNode, BeaconNodeError};
use types::BeaconBlock;
use std::sync::RwLock;

type ProduceResult = Result<Option<BeaconBlock>, BeaconNodeError>;
type PublishResult = Result<bool, BeaconNodeError>;

#[derive(Default)]
pub struct TestBeaconNode {
    pub produce_input: RwLock<Option<u64>>,
    pub produce_result: RwLock<Option<ProduceResult>>,
    pub publish_input: RwLock<Option<BeaconBlock>>,
    pub publish_result: RwLock<Option<PublishResult>>,
}

impl TestBeaconNode {
    pub fn set_next_produce_result(&self, result: ProduceResult) {
        *self.produce_result.write().unwrap() = Some(result);
    }

    pub fn set_next_publish_result(&self, result: PublishResult) {
        *self.publish_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for TestBeaconNode {
    fn produce_beacon_block(&self, slot: u64) -> ProduceResult {
        *self.produce_input.write().unwrap() = Some(slot);
        match *self.produce_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: produce_result == None")
        }
    }

    fn publish_beacon_block(&self, block: BeaconBlock) -> PublishResult {
        *self.publish_input.write().unwrap() = Some(block);
        match *self.publish_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: publish_result == None")
        }
    }
}
