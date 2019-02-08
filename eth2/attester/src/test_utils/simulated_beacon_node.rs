use crate::traits::{BeaconNode, BeaconNodeError, PublishOutcome};
use std::sync::RwLock;
use types::{AttestationData, FreeAttestation, Slot};

type ProposeResult = Result<Option<AttestationData>, BeaconNodeError>;
type PublishResult = Result<PublishOutcome, BeaconNodeError>;

/// A test-only struct used to simulate a Beacon Node.
#[derive(Default)]
pub struct SimulatedBeaconNode {
    pub propose_input: RwLock<Option<(Slot, u64)>>,
    pub propose_result: RwLock<Option<ProposeResult>>,

    pub publish_input: RwLock<Option<FreeAttestation>>,
    pub publish_result: RwLock<Option<PublishResult>>,
}

impl SimulatedBeaconNode {
    pub fn set_next_propose_result(&self, result: ProposeResult) {
        *self.propose_result.write().unwrap() = Some(result);
    }

    pub fn set_next_publish_result(&self, result: PublishResult) {
        *self.publish_result.write().unwrap() = Some(result);
    }
}

impl BeaconNode for SimulatedBeaconNode {
    fn propose_attestation_data(&self, slot: Slot, shard: u64) -> ProposeResult {
        *self.propose_input.write().unwrap() = Some((slot, shard));
        match *self.propose_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: propose_result == None"),
        }
    }

    fn publish_attestation_data(&self, free_attestation: FreeAttestation) -> PublishResult {
        *self.publish_input.write().unwrap() = Some(free_attestation.clone());
        match *self.publish_result.read().unwrap() {
            Some(ref r) => r.clone(),
            None => panic!("TestBeaconNode: publish_result == None"),
        }
    }
}
