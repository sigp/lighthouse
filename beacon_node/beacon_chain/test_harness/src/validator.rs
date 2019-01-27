use super::{BenchingBeaconNode, DirectDuties};
use beacon_chain::BeaconChain;
use block_producer::{test_utils::TestSigner, BlockProducer, Error as PollError};
use db::MemoryDB;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, Keypair};

pub use block_producer::PollOutcome;

#[derive(Debug, PartialEq)]
pub enum ProduceError {
    DidNotProduce(PollOutcome),
    PollError(PollError),
}

pub struct TestValidator {
    pub block_producer: BlockProducer<
        TestingSlotClock,
        BenchingBeaconNode<MemoryDB, TestingSlotClock>,
        DirectDuties<MemoryDB, TestingSlotClock>,
        TestSigner,
    >,
    pub spec: Arc<ChainSpec>,
    pub epoch_map: Arc<DirectDuties<MemoryDB, TestingSlotClock>>,
    pub keypair: Keypair,
    pub beacon_node: Arc<BenchingBeaconNode<MemoryDB, TestingSlotClock>>,
    pub slot_clock: Arc<TestingSlotClock>,
    pub signer: Arc<TestSigner>,
}

impl TestValidator {
    pub fn new(
        keypair: Keypair,
        beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock>>,
    ) -> Self {
        let spec = Arc::new(ChainSpec::foundation());
        let slot_clock = Arc::new(TestingSlotClock::new(0));
        let signer = Arc::new(TestSigner::new(keypair.clone()));
        let beacon_node = Arc::new(BenchingBeaconNode::new(beacon_chain.clone()));
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

    pub fn produce_block(&mut self) -> Result<BeaconBlock, ProduceError> {
        // Using `BenchingBeaconNode`, the validator will always return sucessufully if it tries to
        // publish a block.
        match self.block_producer.poll() {
            Ok(PollOutcome::BlockProduced(_)) => {}
            Ok(outcome) => return Err(ProduceError::DidNotProduce(outcome)),
            Err(error) => return Err(ProduceError::PollError(error)),
        };
        Ok(self
            .beacon_node
            .last_published_block()
            .expect("Unable to obtain produced block."))
    }

    pub fn set_slot(&mut self, slot: u64) {
        self.slot_clock.set_slot(slot)
    }
}
