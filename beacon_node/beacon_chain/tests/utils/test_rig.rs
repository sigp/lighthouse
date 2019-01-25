use super::TestValidator;
pub use beacon_chain::dump::{Error as DumpError, SlotDump};
use beacon_chain::BeaconChain;
#[cfg(test)]
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use types::{ChainSpec, Keypair, Validator};

pub struct TestRig {
    db: Arc<MemoryDB>,
    beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock>>,
    block_store: Arc<BeaconBlockStore<MemoryDB>>,
    state_store: Arc<BeaconStateStore<MemoryDB>>,
    validators: Vec<TestValidator>,
}

impl TestRig {
    pub fn new(mut spec: ChainSpec, validator_count: usize) -> Self {
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));

        let slot_clock = TestingSlotClock::new(0);

        // Remove the validators present in the spec (if any).
        spec.initial_validators = Vec::with_capacity(validator_count);
        spec.initial_balances = Vec::with_capacity(validator_count);

        // Insert `validator_count` new `Validator` records into the spec, retaining the keypairs
        // for later user.
        let mut keypairs = Vec::with_capacity(validator_count);
        for _ in 0..validator_count {
            let keypair = Keypair::random();

            spec.initial_validators.push(Validator {
                pubkey: keypair.pk.clone(),
                ..std::default::Default::default()
            });
            spec.initial_balances.push(32_000_000_000); // 32 ETH

            keypairs.push(keypair);
        }

        // Create the Beacon Chain
        let beacon_chain = Arc::new(
            BeaconChain::genesis(state_store.clone(), block_store.clone(), slot_clock, spec)
                .unwrap(),
        );

        // Spawn the test validator instances.
        let mut validators = Vec::with_capacity(validator_count);
        for keypair in keypairs {
            validators.push(TestValidator::new(keypair.clone(), beacon_chain.clone()));
        }

        Self {
            db,
            beacon_chain,
            block_store,
            state_store,
            validators,
        }
    }

    pub fn produce_next_slot(&mut self) {
        let slot = self
            .beacon_chain
            .present_slot()
            .expect("Unable to determine slot.")
            + 1;

        self.beacon_chain.slot_clock.set_slot(slot);

        let proposer = self
            .beacon_chain
            .block_proposer(slot)
            .expect("Unable to determine proposer.");

        self.validators[proposer].set_slot(slot);
        self.validators[proposer].produce_block().unwrap();
    }

    pub fn chain_dump(&self) -> Result<Vec<SlotDump>, DumpError> {
        self.beacon_chain.chain_dump()
    }
}
