use super::ValidatorHarness;
use beacon_chain::{BeaconChain, BlockProcessingOutcome};
pub use beacon_chain::{BeaconChainError, CheckPoint};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use fork_choice::BitwiseLMDGhost;
use log::debug;
use rayon::prelude::*;
use slot_clock::TestingSlotClock;
use ssz::TreeHash;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::sync::Arc;
use types::{test_utils::TestingBeaconStateBuilder, *};

/// The beacon chain harness simulates a single beacon node with `validator_count` validators connected
/// to it. Each validator is provided a borrow to the beacon chain, where it may read
/// information and submit blocks/attestations for processing.
///
/// This test harness is useful for testing validator and internal state transition logic. It
/// is not useful for testing that multiple beacon nodes can reach consensus.
pub struct BeaconChainHarness {
    pub db: Arc<MemoryDB>,
    pub beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock, BitwiseLMDGhost<MemoryDB>>>,
    pub block_store: Arc<BeaconBlockStore<MemoryDB>>,
    pub state_store: Arc<BeaconStateStore<MemoryDB>>,
    pub validators: Vec<ValidatorHarness>,
    pub spec: Arc<ChainSpec>,
}

impl BeaconChainHarness {
    /// Create a new harness with:
    ///
    /// - A keypair, `BlockProducer` and `Attester` for each validator.
    /// - A new BeaconChain struct where the given validators are in the genesis.
    pub fn new(spec: ChainSpec, validator_count: usize) -> Self {
        let state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);
        Self::from_beacon_state_builder(state_builder, spec)
    }

    pub fn from_beacon_state_builder(
        state_builder: TestingBeaconStateBuilder,
        spec: ChainSpec,
    ) -> Self {
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));
        let slot_clock = TestingSlotClock::new(spec.genesis_slot.as_u64());
        let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

        let (genesis_state, keypairs) = state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.hash_tree_root());

        // Create the Beacon Chain
        let beacon_chain = Arc::new(
            BeaconChain::from_genesis(
                state_store.clone(),
                block_store.clone(),
                slot_clock,
                genesis_state,
                genesis_block,
                spec.clone(),
                fork_choice,
            )
            .unwrap(),
        );

        let spec = Arc::new(spec);

        debug!("Creating validator producer and attester instances...");

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

        let nth_slot = slot
            - slot
                .epoch(self.spec.slots_per_epoch)
                .start_slot(self.spec.slots_per_epoch);
        let nth_epoch = slot.epoch(self.spec.slots_per_epoch) - self.spec.genesis_epoch;
        debug!(
            "Advancing BeaconChain to slot {}, epoch {} (epoch height: {}, slot {} in epoch.).",
            slot,
            slot.epoch(self.spec.slots_per_epoch),
            nth_epoch,
            nth_slot
        );

        self.beacon_chain.slot_clock.set_slot(slot.as_u64());
        self.beacon_chain.advance_state(slot).unwrap();
        slot
    }

    /// Gather the `FreeAttestation`s from the valiators.
    ///
    /// Note: validators will only produce attestations _once per slot_. So, if you call this twice
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
            .fold(vec![], |mut acc, c| {
                acc.append(&mut c.committee.clone());
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

                    // Prompt the validator to produce an attestation (if required).
                    validator.produce_free_attestation().ok()
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
    /// Note: the validator will only produce it _once per slot_. So, if you call this twice you'll
    /// only get a block once.
    pub fn produce_block(&mut self) -> BeaconBlock {
        let present_slot = self.beacon_chain.present_slot();

        let proposer = self.beacon_chain.block_proposer(present_slot).unwrap();

        debug!(
            "Producing block from validator #{} for slot {}.",
            proposer, present_slot
        );

        // Ensure the validators slot clock is accurate.
        self.validators[proposer].set_slot(present_slot);
        self.validators[proposer].produce_block().unwrap()
    }

    /// Advances the chain with a BeaconBlock and attestations from all validators.
    ///
    /// This is the ideal scenario for the Beacon Chain, 100% honest participation from
    /// validators.
    pub fn advance_chain_with_block(&mut self) {
        self.increment_beacon_chain_slot();

        // Produce a new block.
        debug!("Producing block...");
        let block = self.produce_block();
        debug!("Submitting block for processing...");
        match self.beacon_chain.process_block(block) {
            Ok(BlockProcessingOutcome::ValidBlock(_)) => {}
            other => panic!("block processing failed with {:?}", other),
        };
        debug!("...block processed by BeaconChain.");

        debug!("Producing free attestations...");

        // Produce new attestations.
        let free_attestations = self.gather_free_attesations();

        debug!("Processing free attestations...");

        free_attestations.par_iter().for_each(|free_attestation| {
            self.beacon_chain
                .process_free_attestation(free_attestation.clone())
                .unwrap();
        });

        debug!("Free attestations processed.");
    }

    /// Signs a message using some validators secret key with the `Fork` info from the latest state
    /// of the `BeaconChain`.
    ///
    /// Useful for producing slashable messages and other objects that `BeaconChainHarness` does
    /// not produce naturally.
    pub fn validator_sign(
        &self,
        validator_index: usize,
        message: &[u8],
        epoch: Epoch,
        domain_type: Domain,
    ) -> Option<Signature> {
        let validator = self.validators.get(validator_index)?;

        let domain = self
            .spec
            .get_domain(epoch, domain_type, &self.beacon_chain.state.read().fork);

        Some(Signature::new(message, domain, &validator.keypair.sk))
    }

    /// Returns the current `Fork` of the `beacon_chain`.
    pub fn fork(&self) -> Fork {
        self.beacon_chain.state.read().fork.clone()
    }

    /// Returns the current `epoch` of the `beacon_chain`.
    pub fn epoch(&self) -> Epoch {
        self.beacon_chain
            .state
            .read()
            .slot
            .epoch(self.spec.slots_per_epoch)
    }

    /// Returns the keypair for some validator index.
    pub fn validator_keypair(&self, validator_index: usize) -> Option<&Keypair> {
        self.validators
            .get(validator_index)
            .and_then(|v| Some(&v.keypair))
    }

    /// Submit a deposit to the `BeaconChain` and, if given a keypair, create a new
    /// `ValidatorHarness` instance for this validator.
    ///
    /// If a new `ValidatorHarness` was created, the validator should become fully operational as
    /// if the validator were created during `BeaconChainHarness` instantiation.
    pub fn add_deposit(&mut self, deposit: Deposit, keypair: Option<Keypair>) {
        self.beacon_chain.receive_deposit_for_inclusion(deposit);

        // If a keypair is present, add a new `ValidatorHarness` to the rig.
        if let Some(keypair) = keypair {
            let validator =
                ValidatorHarness::new(keypair, self.beacon_chain.clone(), self.spec.clone());
            self.validators.push(validator);
        }
    }

    /// Submit an exit to the `BeaconChain` for inclusion in some block.
    ///
    /// Note: the `ValidatorHarness` for this validator continues to exist. Once it is exited it
    /// will stop receiving duties from the beacon chain and just do nothing when prompted to
    /// produce/attest.
    pub fn add_exit(&mut self, exit: VoluntaryExit) {
        self.beacon_chain.receive_exit_for_inclusion(exit);
    }

    /// Submit an transfer to the `BeaconChain` for inclusion in some block.
    pub fn add_transfer(&mut self, transfer: Transfer) {
        self.beacon_chain.receive_transfer_for_inclusion(transfer);
    }

    /// Submit a proposer slashing to the `BeaconChain` for inclusion in some block.
    pub fn add_proposer_slashing(&mut self, proposer_slashing: ProposerSlashing) {
        self.beacon_chain
            .receive_proposer_slashing_for_inclusion(proposer_slashing);
    }

    /// Submit an attester slashing to the `BeaconChain` for inclusion in some block.
    pub fn add_attester_slashing(&mut self, attester_slashing: AttesterSlashing) {
        self.beacon_chain
            .receive_attester_slashing_for_inclusion(attester_slashing);
    }

    /// Executes the fork choice rule on the `BeaconChain`, selecting a new canonical head.
    pub fn run_fork_choice(&mut self) {
        self.beacon_chain.fork_choice().unwrap()
    }

    /// Dump all blocks and states from the canonical beacon chain.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, BeaconChainError> {
        self.beacon_chain.chain_dump()
    }
}
