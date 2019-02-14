use super::traits::{BeaconNode, BeaconNodeError};
use super::EpochDuties;
use bls::PublicKey;
use std::sync::RwLock;
use types::Epoch;

type ShufflingResult = Result<Option<EpochDuties>, BeaconNodeError>;

/// A test-only struct used to simulate a Beacon Node.
#[derive(Default)]
pub struct TestBeaconNode {
    pub request_shuffling_input: RwLock<Option<(Epoch, PublicKey)>>,
    pub request_shuffling_result: RwLock<Option<ShufflingResult>>,
}

impl TestBeaconNode {
    /// Set the result to be returned when `request_shuffling` is called.
    pub fn set_next_shuffling_result(&self, result: ShufflingResult) {
        *self.request_shuffling_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for TestBeaconNode {
    /// Returns the value specified by the `set_next_shuffling_result`.
    fn request_shuffling(&self, epoch: Epoch, public_key: &PublicKey) -> ShufflingResult {
        *self.request_shuffling_input.write().unwrap() = Some((epoch, public_key.clone()));
        match *self.request_shuffling_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: produce_result == None"),
        }
    }
}
