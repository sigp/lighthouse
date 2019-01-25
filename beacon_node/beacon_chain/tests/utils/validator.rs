use super::{DirectBeaconNode, DirectDuties};
use beacon_chain::BeaconChain;
#[cfg(test)]
use block_producer::{test_utils::TestSigner, BlockProducer, Error as PollError};
use db::MemoryDB;
use slot_clock::TestingSlotClock;
use spec::ChainSpec;
use std::sync::{Arc, RwLock};
use types::{Keypair, Validator};

pub use block_producer::PollOutcome;

#[derive(Debug, PartialEq)]
pub enum ProduceError {
    DidNotProduce(PollOutcome),
    PollError(PollError),
}

pub struct TestValidator {
    block_producer: BlockProducer<
        TestingSlotClock,
        DirectBeaconNode<MemoryDB, TestingSlotClock>,
        DirectDuties<MemoryDB, TestingSlotClock>,
        TestSigner,
    >,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<DirectDuties<MemoryDB, TestingSlotClock>>,
    keypair: Keypair,
    beacon_node: Arc<DirectBeaconNode<MemoryDB, TestingSlotClock>>,
    slot_clock: Arc<TestingSlotClock>,
    signer: Arc<TestSigner>,
}

impl TestValidator {
    pub fn new(
        keypair: Keypair,
        beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock>>,
    ) -> Self {
        let spec = Arc::new(ChainSpec::foundation());
        let slot_clock = Arc::new(TestingSlotClock::new(0));
        let signer = Arc::new(TestSigner::new(keypair.clone()));
        let beacon_node = Arc::new(DirectBeaconNode::new(beacon_chain.clone()));
        let epoch_map = Arc::new(DirectDuties::new(keypair.pk.clone(), beacon_chain.clone()));

        let block_producer = BlockProducer::new(
            spec.clone(),
            keypair.pk.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        Self {
            block_producer,
            spec,
            epoch_map,
            keypair,
            beacon_node,
            slot_clock,
            signer,
        }
    }

    pub fn produce_block(&mut self) -> Result<PollOutcome, ProduceError> {
        match self.block_producer.poll() {
            Ok(PollOutcome::BlockProduced(slot)) => Ok(PollOutcome::BlockProduced(slot)),
            Ok(outcome) => Err(ProduceError::DidNotProduce(outcome)),
            Err(error) => Err(ProduceError::PollError(error)),
        }
    }

    pub fn set_slot(&mut self, slot: u64) {
        self.slot_clock.set_slot(slot)
    }
}
