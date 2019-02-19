// Tests the optimised LMD Ghost Algorithm

extern crate beacon_chain;
extern crate bls;
extern crate db;
extern crate env_logger;
extern crate fork_choice;
extern crate log;
extern crate slot_clock;
extern crate types;
extern crate yaml_rust;

pub use beacon_chain::BeaconChain;
use bls::{PublicKey, Signature};
use db::stores::{BeaconBlockStore, BeaconStateStore};
use db::MemoryDB;
use env_logger::{Builder, Env};
use fork_choice::{ForkChoice, ForkChoiceAlgorithm, LongestChain, OptimisedLMDGhost, SlowLMDGhost};
use ssz::ssz_encode;
use std::collections::HashMap;
use std::sync::Arc;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::{
    BeaconBlock, BeaconBlockBody, BeaconState, ChainSpec, Epoch, Eth1Data, Hash256, Slot, Validator,
};
use yaml_rust::yaml;

// run tests
#[test]
fn test_optimised_lmd_ghost() {
    test_yaml_vectors(
        ForkChoiceAlgorithm::OptimisedLMDGhost,
        "tests/optimised_lmd_ghost_test_vectors.yaml",
        100,
    );
}

// run a generic test over given YAML test vectors
fn test_yaml_vectors(
    fork_choice_algo: ForkChoiceAlgorithm,
    yaml_file_path: &str,
    max_validators: usize,
) {
    // set up logging
    Builder::from_env(Env::default().default_filter_or("debug")).init();

    // load test cases from yaml
    let test_cases = load_test_cases_from_yaml(yaml_file_path);

    // set up the test
    let total_emulated_validators = max_validators; // the number of validators used to give weights.
    let (mut fork_choice, block_store, state_root) =
        setup_inital_state(fork_choice_algo, total_emulated_validators);

    // keep a hashmap of block_id's to block_hashes (random hashes to abstract block_id)
    let mut block_id_map: HashMap<String, Hash256> = HashMap::new();
    // keep a list of hash to slot
    let mut block_slot: HashMap<Hash256, Slot> = HashMap::new();

    // default vars
    let spec = ChainSpec::foundation();
    let zero_hash = Hash256::zero();
    let eth1_data = Eth1Data {
        deposit_root: zero_hash.clone(),
        block_hash: zero_hash.clone(),
    };
    let randao_reveal = Signature::empty_signature();
    let signature = Signature::empty_signature();
    let body = BeaconBlockBody {
        proposer_slashings: vec![],
        attester_slashings: vec![],
        attestations: vec![],
        deposits: vec![],
        exits: vec![],
    };

    // process the tests
    for test_case in test_cases {
        // assume the block tree is given to us in order.
        for block in test_case["blocks"].clone().into_vec().unwrap() {
            let block_id = block["id"].as_str().unwrap().to_string();
            let parent_id = block["parent"].as_str().unwrap();

            // default params for genesis
            let mut block_hash = zero_hash.clone();
            let mut slot = spec.genesis_slot;
            let mut parent_root = zero_hash;

            // set the slot and parent based off the YAML. Start with genesis;
            // if not the genesis, update slot and parent
            if parent_id != block_id {
                // generate a random hash for the block_hash
                block_hash = Hash256::random();
                // find the parent hash
                parent_root = *block_id_map
                    .get(parent_id)
                    .expect(&format!("Parent not found: {}", parent_id));
                slot = *(block_slot
                    .get(&parent_root)
                    .expect("Parent should have a slot number"))
                    + 1;
            }

            block_id_map.insert(block_id.clone(), block_hash.clone());

            // update slot mapping
            block_slot.insert(block_hash, slot);

            // build the BeaconBlock
            let beacon_block = BeaconBlock {
                slot,
                parent_root,
                state_root: state_root.clone(),
                randao_reveal: randao_reveal.clone(),
                eth1_data: eth1_data.clone(),
                signature: signature.clone(),
                body: body.clone(),
            };

            // Store the block and state.
            block_store
                .put(&block_hash, &ssz_encode(&beacon_block)[..])
                .unwrap();

            // run add block for fork choice if not genesis
            if parent_id != block_id {
                fork_choice
                    .add_block(&beacon_block, &block_hash, &spec)
                    .unwrap();
            }
        }

        // add the weights (attestations)
        let mut current_validator = 0;
        for id_map in test_case["weights"].clone().into_vec().unwrap() {
            // get the block id and weights
            for (map_id, map_weight) in id_map.as_hash().unwrap().iter() {
                let id = map_id.as_str().unwrap();
                let block_root = block_id_map
                    .get(id)
                    .expect(&format!("Cannot find block id: {} in weights", id));
                let weight = map_weight.as_i64().unwrap();
                // we assume a validator has a value 1 and add an attestation for to achieve the
                // correct weight
                for _ in 0..weight {
                    assert!(current_validator <= total_emulated_validators);
                    fork_choice
                        .add_attestation(current_validator as u64, &block_root, &spec)
                        .unwrap();
                    current_validator += 1;
                }
            }
        }

        // everything is set up, run the fork choice, using genesis as the head
        let head = fork_choice.find_head(&zero_hash, &spec).unwrap();

        let (found_id, _) = block_id_map
            .iter()
            .find(|(_, hash)| **hash == head)
            .unwrap();

        // compare the result to the expected test
        let success = test_case["heads"]
            .clone()
            .into_vec()
            .unwrap()
            .iter()
            .find(|heads| heads["id"].as_str().unwrap() == found_id)
            .is_some();

        println!("Head Block ID: {:?}", found_id);
        assert!(success, "Did not find one of the possible heads");
    }
}

// loads the test_cases from the supplied yaml file
fn load_test_cases_from_yaml(file_path: &str) -> Vec<yaml_rust::Yaml> {
    // load the yaml
    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push(file_path);
        File::open(file_path_buf).unwrap()
    };
    let mut yaml_str = String::new();
    file.read_to_string(&mut yaml_str).unwrap();
    let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
    let doc = &docs[0];
    doc["test_cases"].as_vec().unwrap().clone()
}

// initialise a single validator and state. All blocks will reference this state root.
fn setup_inital_state(
    fork_choice_algo: ForkChoiceAlgorithm,
    no_validators: usize,
) -> (Box<ForkChoice>, Arc<BeaconBlockStore<MemoryDB>>, Hash256) {
    let zero_hash = Hash256::zero();

    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    // the fork choice instantiation
    let fork_choice: Box<ForkChoice> = match fork_choice_algo {
        ForkChoiceAlgorithm::OptimisedLMDGhost => Box::new(OptimisedLMDGhost::new(
            block_store.clone(),
            state_store.clone(),
        )),
        ForkChoiceAlgorithm::SlowLMDGhost => {
            Box::new(SlowLMDGhost::new(block_store.clone(), state_store.clone()))
        }
        ForkChoiceAlgorithm::LongestChain => Box::new(LongestChain::new(block_store.clone())),
    };

    // misc vars for setting up the state
    let genesis_time = 1_550_381_159;

    let latest_eth1_data = Eth1Data {
        deposit_root: zero_hash.clone(),
        block_hash: zero_hash.clone(),
    };

    let initial_validator_deposits = vec![];
    let spec = ChainSpec::foundation();

    // create the state
    let mut state = BeaconState::genesis(
        genesis_time,
        initial_validator_deposits,
        latest_eth1_data,
        &spec,
    )
    .unwrap();

    let default_validator = Validator {
        pubkey: PublicKey::default(),
        withdrawal_credentials: zero_hash,
        activation_epoch: Epoch::from(0u64),
        exit_epoch: spec.far_future_epoch,
        withdrawal_epoch: spec.far_future_epoch,
        penalized_epoch: spec.far_future_epoch,
        status_flags: None,
    };
    // activate the validators
    for _ in 0..no_validators {
        state.validator_registry.push(default_validator.clone());
        state.validator_balances.push(32_000_000_000);
    }

    let state_root = state.canonical_root();
    state_store
        .put(&state_root, &ssz_encode(&state)[..])
        .unwrap();

    // return initialised vars
    (fork_choice, block_store, state_root)
}
