use super::{DirectBeaconNode, DirectDuties, TestValidator};
use beacon_chain::BeaconChain;
#[cfg(test)]
use block_producer::{test_utils::TestSigner, BlockProducer};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use slot_clock::TestingSlotClock;
use spec::ChainSpec;
use std::sync::{Arc, RwLock};
use types::{Keypair, Validator};

pub struct TestRig<'a> {
    db: Arc<MemoryDB>,
    beacon_chain: BeaconChain<MemoryDB, TestingSlotClock>,
    block_store: Arc<BeaconBlockStore<MemoryDB>>,
    state_store: Arc<BeaconStateStore<MemoryDB>>,
    validators: Vec<TestValidator<'a>>,
}

impl<'a> TestRig<'a> {
    pub fn new(spec: ChainSpec) -> Self {
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));

        let slot_clock = TestingSlotClock::new(0);

        let mut beacon_chain =
            BeaconChain::genesis(state_store.clone(), block_store.clone(), slot_clock, spec)
                .unwrap();

        /*
        let validators = generate_validators(validator_count, &beacon_chain);
        beacon_chain.spec = inject_validators_into_spec(beacon_chain.spec.clone(), &validators[..]);
        */

        Self {
            db,
            beacon_chain,
            block_store,
            state_store,
            validators: vec![],
        }
    }

    pub fn generate_validators(&'a mut self, validator_count: usize) {
        self.validators = Vec::with_capacity(validator_count);
        for _ in 0..validator_count {
            self.validators.push(TestValidator::new(&self.beacon_chain));
        }
        self.beacon_chain.spec =
            inject_validators_into_spec(self.beacon_chain.spec.clone(), &self.validators[..]);
    }

    pub fn process_next_slot(&mut self) {
        let slot = self
            .beacon_chain
            .present_slot()
            .expect("Unable to determine slot.")
            + 1;
        self.beacon_chain.slot_clock.set_slot(slot);

        let block_proposer = self
            .beacon_chain
            .block_proposer(slot)
            .expect("Unable to determine proposer.");

        let validator = self
            .validators
            .get(block_proposer)
            .expect("Block proposer unknown");
    }
}

fn inject_validators_into_spec(mut spec: ChainSpec, validators: &[TestValidator]) -> ChainSpec {
    spec.initial_validators = Vec::with_capacity(validators.len());
    spec.initial_balances = Vec::with_capacity(validators.len());
    for validator in validators {
        spec.initial_validators.push(validator.validator_record());
        spec.initial_balances.push(32_000_000_000); // 32 ETH
    }
    spec
}
