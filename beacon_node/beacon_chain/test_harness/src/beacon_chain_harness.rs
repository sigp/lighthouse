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
use std::sync::Arc;
use types::{test_utils::TestingBeaconStateBuilder, *};

type TestingBeaconChain = BeaconChain<MemoryDB, TestingSlotClock, BitwiseLMDGhost<MemoryDB>>;

/// The beacon chain harness simulates a single beacon node with `validator_count` validators connected
/// to it. Each validator is provided a borrow to the beacon chain, where it may read
/// information and submit blocks/attestations for processing.
///
/// This test harness is useful for testing validator and internal state transition logic. It
/// is not useful for testing that multiple beacon nodes can reach consensus.
pub struct BeaconChainHarness {
    pub db: Arc<MemoryDB>,
    pub beacon_chain: Arc<TestingBeaconChain>,
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

        let (mut genesis_state, keypairs) = state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.hash_tree_root());

        genesis_state
            .build_epoch_cache(RelativeEpoch::Previous, &spec)
            .unwrap();
        genesis_state
            .build_epoch_cache(RelativeEpoch::Current, &spec)
            .unwrap();
        genesis_state
            .build_epoch_cache(RelativeEpoch::NextWithoutRegistryChange, &spec)
            .unwrap();
        genesis_state
            .build_epoch_cache(RelativeEpoch::NextWithRegistryChange, &spec)
            .unwrap();

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
        self.beacon_chain
            .catchup_state()
            .expect("Failed to catch state");
        slot
    }

    pub fn gather_attesations(&mut self) -> Vec<Attestation> {
        let present_slot = self.beacon_chain.present_slot();
        let state = self.beacon_chain.state.read();

        let mut attestations = vec![];

        for committee in state
            .get_crosslink_committees_at_slot(present_slot, &self.spec)
            .unwrap()
        {
            for &validator in &committee.committee {
                let duties = state
                    .get_attestation_duties(validator, &self.spec)
                    .unwrap()
                    .expect("Attesting validators by definition have duties");

                // Obtain `AttestationData` from the beacon chain.
                let data = self
                    .beacon_chain
                    .produce_attestation_data(duties.shard)
                    .unwrap();

                // Produce an aggregate signature with a single signature.
                let aggregate_signature = {
                    let message = AttestationDataAndCustodyBit {
                        data: data.clone(),
                        custody_bit: false,
                    }
                    .hash_tree_root();
                    let domain = self.spec.get_domain(
                        state.slot.epoch(self.spec.slots_per_epoch),
                        Domain::Attestation,
                        &state.fork,
                    );
                    let sig =
                        Signature::new(&message, domain, &self.validators[validator].keypair.sk);

                    let mut agg_sig = AggregateSignature::new();
                    agg_sig.add(&sig);

                    agg_sig
                };

                let mut aggregation_bitfield = Bitfield::with_capacity(duties.committee_len);
                let custody_bitfield = Bitfield::with_capacity(duties.committee_len);

                aggregation_bitfield.set(duties.committee_index, true);

                attestations.push(Attestation {
                    aggregation_bitfield,
                    data,
                    custody_bitfield,
                    aggregate_signature,
                })
            }
        }

        attestations
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
        let block = self.validators[proposer].produce_block().unwrap();

        block
    }

    /// Advances the chain with a BeaconBlock and attestations from all validators.
    ///
    /// This is the ideal scenario for the Beacon Chain, 100% honest participation from
    /// validators.
    pub fn advance_chain_with_block(&mut self) -> BeaconBlock {
        self.increment_beacon_chain_slot();

        // Produce a new block.
        let block = self.produce_block();
        debug!("Submitting block for processing...");
        match self.beacon_chain.process_block(block.clone()) {
            Ok(BlockProcessingOutcome::ValidBlock(_)) => {}
            other => panic!("block processing failed with {:?}", other),
        };
        debug!("...block processed by BeaconChain.");

        debug!("Producing attestations...");

        // Produce new attestations.
        let attestations = self.gather_attesations();

        debug!("Processing {} attestations...", attestations.len());

        attestations
            .par_iter()
            .enumerate()
            .for_each(|(i, attestation)| {
                self.beacon_chain
                    .process_attestation(attestation.clone())
                    .expect(&format!("Attestation {} invalid: {:?}", i, attestation));
            });

        debug!("Attestations processed.");

        block
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
        self.beacon_chain.process_deposit(deposit).unwrap();

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
        self.beacon_chain.process_voluntary_exit(exit).unwrap();
    }

    /// Submit an transfer to the `BeaconChain` for inclusion in some block.
    pub fn add_transfer(&mut self, transfer: Transfer) {
        self.beacon_chain.process_transfer(transfer).unwrap();
    }

    /// Submit a proposer slashing to the `BeaconChain` for inclusion in some block.
    pub fn add_proposer_slashing(&mut self, proposer_slashing: ProposerSlashing) {
        self.beacon_chain
            .process_proposer_slashing(proposer_slashing)
            .unwrap();
    }

    /// Submit an attester slashing to the `BeaconChain` for inclusion in some block.
    pub fn add_attester_slashing(&mut self, attester_slashing: AttesterSlashing) {
        self.beacon_chain
            .process_attester_slashing(attester_slashing)
            .unwrap();
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
