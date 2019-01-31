use attester::{Attester, Error as AttestationPollError};
use beacon_chain::BeaconChain;
use block_producer::{BlockProducer, Error as BlockPollError};
use db::MemoryDB;
use signer::TestSigner;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, FreeAttestation, Keypair};
mod beacon_node;
mod direct_duties;
mod signer;

pub use self::beacon_node::BenchingBeaconNode;
pub use self::direct_duties::DirectDuties;
pub use attester::PollOutcome as AttestationPollOutcome;
pub use block_producer::PollOutcome as BlockPollOutcome;

#[derive(Debug, PartialEq)]
pub enum BlockProduceError {
    DidNotProduce(BlockPollOutcome),
    PollError(BlockPollError),
}

#[derive(Debug, PartialEq)]
pub enum AttestationProduceError {
    DidNotProduce(AttestationPollOutcome),
    PollError(AttestationPollError),
}

pub struct TestValidator {
    pub block_producer: BlockProducer<
        TestingSlotClock,
        BenchingBeaconNode<MemoryDB, TestingSlotClock>,
        DirectDuties<MemoryDB, TestingSlotClock>,
        TestSigner,
    >,
    pub attester: Attester<
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
        spec: Arc<ChainSpec>,
    ) -> Self {
        let slot_clock = Arc::new(TestingSlotClock::new(spec.genesis_slot));
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

        let attester = Attester::new(
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        Self {
            block_producer,
            attester,
            spec,
            epoch_map,
            keypair,
            beacon_node,
            slot_clock,
            signer,
        }
    }

    pub fn produce_block(&mut self) -> Result<BeaconBlock, BlockProduceError> {
        // Using `BenchingBeaconNode`, the validator will always return sucessufully if it tries to
        // publish a block.
        match self.block_producer.poll() {
            Ok(BlockPollOutcome::BlockProduced(_)) => {}
            Ok(outcome) => return Err(BlockProduceError::DidNotProduce(outcome)),
            Err(error) => return Err(BlockProduceError::PollError(error)),
        };
        Ok(self
            .beacon_node
            .last_published_block()
            .expect("Unable to obtain produced block."))
    }

    pub fn produce_free_attestation(&mut self) -> Result<FreeAttestation, AttestationProduceError> {
        match self.attester.poll() {
            Ok(AttestationPollOutcome::AttestationProduced(_)) => {}
            Ok(outcome) => return Err(AttestationProduceError::DidNotProduce(outcome)),
            Err(error) => return Err(AttestationProduceError::PollError(error)),
        };
        Ok(self
            .beacon_node
            .last_published_free_attestation()
            .expect("Unable to obtain produced attestation."))
    }

    pub fn set_slot(&mut self, slot: u64) {
        self.slot_clock.set_slot(slot)
    }
}
