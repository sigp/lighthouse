use super::traits::{BeaconNode, BeaconNodeError};
use super::EpochDuties;
use bls::PublicKey;
use std::sync::RwLock;

type ShufflingResult = Result<Option<EpochDuties>, BeaconNodeError>;

#[derive(Default)]
pub struct TestBeaconNode {
    pub request_shuffling_input: RwLock<Option<(u64, PublicKey)>>,
    pub request_shuffling_result: RwLock<Option<ShufflingResult>>,
}

impl TestBeaconNode {
    pub fn set_next_shuffling_result(&self, result: ShufflingResult) {
        *self.request_shuffling_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for TestBeaconNode {
    fn request_shuffling(&self, epoch: u64, public_key: &PublicKey) -> ShufflingResult {
        *self.request_shuffling_input.write().unwrap() = Some((epoch, public_key.clone()));
        match *self.request_shuffling_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: produce_result == None"),
        }
    }
}
