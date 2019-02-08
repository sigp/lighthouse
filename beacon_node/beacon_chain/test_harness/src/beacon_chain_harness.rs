use super::ValidatorHarness;
use beacon_chain::BeaconChain;
pub use beacon_chain::{CheckPoint, Error as BeaconChainError};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use log::debug;
use rayon::prelude::*;
use slot_clock::TestingSlotClock;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, FreeAttestation, Keypair, Slot, Validator};

/// The beacon chain harness simulates a single beacon node with `validator_count` validators connected
/// to it. Each validator is provided a borrow to the beacon chain, where it may read
/// information and submit blocks/attesations for processing.
///
/// This test harness is useful for testing validator and internal state transition logic. It
/// is not useful for testing that multiple beacon nodes can reach consensus.
pub struct BeaconChainHarness {
    pub db: Arc<MemoryDB>,
    pub beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock>>,
    pub block_store: Arc<BeaconBlockStore<MemoryDB>>,
    pub state_store: Arc<BeaconStateStore<MemoryDB>>,
    pub validators: Vec<ValidatorHarness>,
    pub spec: Arc<ChainSpec>,
}

impl BeaconChainHarness {
    /// Create a new harness with:
    ///
    /// - A keypair, `BlockProposer` and `Attester` for each validator.
    /// - A new BeaconChain struct where the given validators are in the genesis.
    pub fn new(mut spec: ChainSpec, validator_count: usize) -> Self {
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));

        let slot_clock = TestingSlotClock::new(spec.genesis_slot.as_u64());

        // Remove the validators present in the spec (if any).
        spec.initial_validators = Vec::with_capacity(validator_count);
        spec.initial_balances = Vec::with_capacity(validator_count);

        debug!("Generating validator keypairs...");

        let keypairs: Vec<Keypair> = (0..validator_count)
            .collect::<Vec<usize>>()
            .par_iter()
            .map(|_| Keypair::random())
            .collect();

        debug!("Creating validator records...");

        spec.initial_validators = keypairs
            .par_iter()
            .map(|keypair| Validator {
                pubkey: keypair.pk.clone(),
                activation_slot: Slot::new(0),
                ..std::default::Default::default()
            })
            .collect();

        debug!("Setting validator balances...");

        spec.initial_balances = spec
            .initial_validators
            .par_iter()
            .map(|_| 32_000_000_000) // 32 ETH
            .collect();

        debug!("Creating the BeaconChain...");

        // Create the Beacon Chain
        let beacon_chain = Arc::new(
            BeaconChain::genesis(
                state_store.clone(),
                block_store.clone(),
                slot_clock,
                spec.clone(),
            )
            .unwrap(),
        );

        let spec = Arc::new(spec);

        debug!("Creating validator proposer and attester instances...");

        // Spawn the test validator instances.
        let validators: Vec<ValidatorHarness> = keypairs
            .iter()
            .map(|keypair| {
                ValidatorHarness::new(keypair.clone(), beacon_chain.clone(), spec.clone())
            })
            .collect();

        debug!("Created {} ValidatorHarnesss", validators.len());

        Self {
            db,
            beacon_chain,
            block_store,
            state_store,
            validators,
            spec,
        }
    }

    /// Move the `slot_clock` for the `BeaconChain` forward one slot.
    ///
    /// This is the equivalent of advancing a system clock forward one `SLOT_DURATION`.
    ///
    /// Returns the new slot.
    pub fn increment_beacon_chain_slot(&mut self) -> Slot {
        let slot = self.beacon_chain.present_slot() + 1;

        debug!("Incrementing BeaconChain slot to {}.", slot);

        self.beacon_chain.slot_clock.set_slot(slot.as_u64());
        self.beacon_chain.advance_state(slot).unwrap();
        slot
    }

    /// Gather the `FreeAttestation`s from the valiators.
    ///
    /// Note: validators will only propose attestations _once per slot_. So, if you call this twice
    /// you'll only get attestations on the first run.
    pub fn gather_free_attesations(&mut self) -> Vec<FreeAttestation> {
        let present_slot = self.beacon_chain.present_slot();

        let attesting_validators = self
            .beacon_chain
            .state
            .read()
            .get_crosslink_committees_at_slot(present_slot, &self.spec)
            .unwrap()
            .iter()
            .fold(vec![], |mut acc, (committee, _slot)| {
                acc.append(&mut committee.clone());
                acc
            });
        let attesting_validators: HashSet<usize> =
            HashSet::from_iter(attesting_validators.iter().cloned());

        let free_attestations: Vec<FreeAttestation> = self
            .validators
            .par_iter_mut()
            .enumerate()
            .filter_map(|(i, validator)| {
                if attesting_validators.contains(&i) {
                    // Advance the validator slot.
                    validator.set_slot(present_slot);

                    // Prompt the validator to propose an attestation (if required).
                    validator.propose_free_attestation().ok()
                } else {
                    None
                }
            })
            .collect();

        debug!(
            "Gathered {} FreeAttestations for slot {}.",
            free_attestations.len(),
            present_slot
        );

        free_attestations
    }

    /// Get the block from the proposer for the slot.
    ///
    /// Note: the validator will only propose it _once per slot_. So, if you call this twice you'll
    /// only get a block once.
    pub fn propose_block(&mut self) -> BeaconBlock {
        let present_slot = self.beacon_chain.present_slot();

        let proposer = self.beacon_chain.block_proposer(present_slot).unwrap();

        debug!(
            "Producing block from validator #{} for slot {}.",
            proposer, present_slot
        );

        // Ensure the validators slot clock is accurate.
        self.validators[proposer].set_slot(present_slot);
        self.validators[proposer].propose_block().unwrap()
    }

    /// Advances the chain with a BeaconBlock and attestations from all validators.
    ///
    /// This is the ideal scenario for the Beacon Chain, 100% honest participation from
    /// validators.
    pub fn advance_chain_with_block(&mut self) {
        self.increment_beacon_chain_slot();

        // Propose a new block.
        let block = self.propose_block();
        debug!("Submitting block for processing...");
        self.beacon_chain.process_block(block).unwrap();
        debug!("...block processed by BeaconChain.");

        debug!("Producing free attestations...");

        // Propose new attestations.
        let free_attestations = self.gather_free_attesations();

        debug!("Processing free attestations...");

        free_attestations.par_iter().for_each(|free_attestation| {
            self.beacon_chain
                .process_free_attestation(free_attestation.clone())
                .unwrap();
        });

        debug!("Free attestations processed.");
    }

    /// Dump all blocks and states from the canonical beacon chain.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, BeaconChainError> {
        self.beacon_chain.chain_dump()
    }

    /// Write the output of `chain_dump` to a JSON file.
    pub fn dump_to_file(&self, filename: String, chain_dump: &Vec<CheckPoint>) {
        let json = serde_json::to_string(chain_dump).unwrap();
        let mut file = File::create(filename).unwrap();
        file.write_all(json.as_bytes())
            .expect("Failed writing dump to file.");
    }
}
