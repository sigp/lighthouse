use crate::traits::{BeaconNode, BeaconNodeError, PublishOutcome};
use std::sync::RwLock;
use types::{AttestationData, Attestation, Slot};

type ProduceResult = Result<Option<AttestationData>, BeaconNodeError>;
type PublishResult = Result<PublishOutcome, BeaconNodeError>;

/// A test-only struct used to simulate a Beacon Node.
#[derive(Default)]
pub struct SimulatedBeaconNode {
    pub produce_input: RwLock<Option<(Slot, u64)>>,
    pub produce_result: RwLock<Option<ProduceResult>>,

    pub publish_input: RwLock<Option<Attestation>>,
    pub publish_result: RwLock<Option<PublishResult>>,
}

impl SimulatedBeaconNode {
    pub fn set_next_produce_result(&self, result: ProduceResult) {
        *self.produce_result.write().unwrap() = Some(result);
    }

    pub fn set_next_publish_result(&self, result: PublishResult) {
        *self.publish_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for SimulatedBeaconNode {
    fn produce_attestation_data(&self, slot: Slot, shard: u64) -> ProduceResult {
        *self.produce_input.write().unwrap() = Some((slot, shard));
        match *self.produce_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: produce_result == None"),
        }
    }

    fn publish_attestation(&self, attestation: Attestation) -> PublishResult {
        *self.publish_input.write().unwrap() = Some(attestation.clone());
        match *self.publish_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: publish_result == None"),
        }
    }
}
