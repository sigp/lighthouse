use super::ValidatorHarness;
use beacon_chain::{BeaconChain, BlockProcessingOutcome};
pub use beacon_chain::{CheckPoint, Error as BeaconChainError};
use bls::create_proof_of_possession;
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
use std::fs::File;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::sync::Arc;
use types::*;

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
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));
        let genesis_time = 1_549_935_547; // 12th Feb 2018 (arbitrary value in the past).
        let slot_clock = TestingSlotClock::new(spec.genesis_slot.as_u64());
        let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());
        let latest_eth1_data = Eth1Data {
            deposit_root: Hash256::zero(),
            block_hash: Hash256::zero(),
        };

        debug!("Generating validator keypairs...");

        let keypairs: Vec<Keypair> = (0..validator_count)
            .collect::<Vec<usize>>()
            .par_iter()
            .map(|_| Keypair::random())
            .collect();

        debug!("Creating validator deposits...");

        let initial_validator_deposits = keypairs
            .par_iter()
            .map(|keypair| Deposit {
                branch: vec![], // branch verification is not specified.
                index: 0,       // index verification is not specified.
                deposit_data: DepositData {
                    amount: 32_000_000_000, // 32 ETH (in Gwei)
                    timestamp: genesis_time - 1,
                    deposit_input: DepositInput {
                        pubkey: keypair.pk.clone(),
                        withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                        proof_of_possession: create_proof_of_possession(&keypair),
                    },
                },
            })
            .collect();

        debug!("Creating the BeaconChain...");

        // Create the Beacon Chain
        let beacon_chain = Arc::new(
            BeaconChain::genesis(
                state_store.clone(),
                block_store.clone(),
                slot_clock,
                genesis_time,
                latest_eth1_data,
                initial_validator_deposits,
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
                .epoch(self.spec.epoch_length)
                .start_slot(self.spec.epoch_length);
        let nth_epoch = slot.epoch(self.spec.epoch_length) - self.spec.genesis_epoch;
        debug!(
            "Advancing BeaconChain to slot {}, epoch {} (epoch height: {}, slot {} in epoch.).",
            slot,
            slot.epoch(self.spec.epoch_length),
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

    pub fn validator_sign(
        &self,
        validator_index: usize,
        message: &[u8],
        epoch: Epoch,
        domain_type: u64,
    ) -> Option<Signature> {
        let validator = self.validators.get(validator_index)?;

        let domain = self
            .beacon_chain
            .state
            .read()
            .fork
            .get_domain(epoch, domain_type);

        Some(Signature::new(message, domain, &validator.keypair.sk))
    }

    pub fn add_deposit(&mut self, deposit: Deposit, keypair: Option<Keypair>) {
        self.beacon_chain.receive_deposit_for_inclusion(deposit);

        // If a keypair is present, add a new `ValidatorHarness` to the rig.
        if let Some(keypair) = keypair {
            let validator =
                ValidatorHarness::new(keypair, self.beacon_chain.clone(), self.spec.clone());
            self.validators.push(validator);
        }
    }

    pub fn add_proposer_slashing(&mut self, mut proposer_slashing: ProposerSlashing) {
        let validator = &self.validators[proposer_slashing.proposer_index as usize];

        // This following code is a little awkward, but managing the data_1 and data_1 was getting
        // rather confusing. I think this is better
        let proposals = vec![
            &proposer_slashing.proposal_data_1,
            &proposer_slashing.proposal_data_2,
        ];
        let signatures: Vec<Signature> = proposals
            .iter()
            .map(|proposal_data| {
                let message = proposal_data.hash_tree_root();
                let epoch = proposal_data.slot.epoch(self.spec.epoch_length);
                let domain = self
                    .beacon_chain
                    .state
                    .read()
                    .fork
                    .get_domain(epoch, self.spec.domain_proposal);
                Signature::new(&message[..], domain, &validator.keypair.sk)
            })
            .collect();
        proposer_slashing.proposal_signature_1 = signatures[0].clone();
        proposer_slashing.proposal_signature_2 = signatures[1].clone();

        self.beacon_chain
            .receive_proposer_slashing_for_inclusion(proposer_slashing);
    }

    pub fn add_attester_slashing(&mut self, attester_slashing: AttesterSlashing) {
        self.beacon_chain
            .receive_attester_slashing_for_inclusion(attester_slashing);
    }

    pub fn run_fork_choice(&mut self) {
        self.beacon_chain.fork_choice().unwrap()
    }

    /// Dump all blocks and states from the canonical beacon chain.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, BeaconChainError> {
        self.beacon_chain.chain_dump()
    }

    /// Write the output of `chain_dump` to a JSON file.
    pub fn dump_to_file(&self, filename: String, chain_dump: &[CheckPoint]) {
        let json = serde_json::to_string(chain_dump).unwrap();
        let mut file = File::create(filename).unwrap();
        file.write_all(json.as_bytes())
            .expect("Failed writing dump to file.");
    }
}
