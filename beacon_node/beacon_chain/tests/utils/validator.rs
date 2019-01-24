use super::{DirectBeaconNode, DirectDuties};
use beacon_chain::BeaconChain;
#[cfg(test)]
use block_producer::{test_utils::TestSigner, BlockProducer};
use db::MemoryDB;
use slot_clock::TestingSlotClock;
use spec::ChainSpec;
use std::sync::{Arc, RwLock};
use types::{Keypair, Validator};

pub struct TestValidator<'a> {
    block_producer: BlockProducer<
        TestingSlotClock,
        DirectBeaconNode<'a, MemoryDB, TestingSlotClock>,
        DirectDuties<'a, MemoryDB, TestingSlotClock>,
        TestSigner,
    >,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<DirectDuties<'a, MemoryDB, TestingSlotClock>>,
    keypair: Keypair,
    beacon_node: Arc<DirectBeaconNode<'a, MemoryDB, TestingSlotClock>>,
    slot_clock: Arc<RwLock<TestingSlotClock>>,
    signer: Arc<TestSigner>,
}

impl<'a> TestValidator<'a> {
    pub fn new(beacon_chain: &'a BeaconChain<MemoryDB, TestingSlotClock>) -> Self {
        let spec = Arc::new(ChainSpec::foundation());
        let keypair = Keypair::random();
        let slot_clock = Arc::new(RwLock::new(TestingSlotClock::new(0)));
        let signer = Arc::new(TestSigner::new(keypair.clone()));
        let beacon_node = Arc::new(DirectBeaconNode::new(beacon_chain));
        let epoch_map = Arc::new(DirectDuties::new(keypair.pk.clone(), beacon_chain));

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

    pub fn validator_record(&self) -> Validator {
        Validator {
            pubkey: self.keypair.pk.clone(),
            ..std::default::Default::default()
        }
    }
}
