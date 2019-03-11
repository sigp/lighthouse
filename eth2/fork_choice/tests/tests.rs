// Tests the available fork-choice algorithms

extern crate beacon_chain;
extern crate bls;
extern crate db;
//extern crate env_logger; // for debugging
extern crate fork_choice;
extern crate hex;
extern crate log;
extern crate slot_clock;
extern crate types;
extern crate yaml_rust;

pub use beacon_chain::BeaconChain;
use bls::Signature;
use db::stores::{BeaconBlockStore, BeaconStateStore};
use db::MemoryDB;
//use env_logger::{Builder, Env};
use fork_choice::{BitwiseLMDGhost, ForkChoice, ForkChoiceAlgorithm, LongestChain, SlowLMDGhost};
use ssz::ssz_encode;
use std::collections::HashMap;
use std::sync::Arc;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::test_utils::TestingBeaconStateBuilder;
use types::{BeaconBlock, BeaconBlockBody, ChainSpec, Eth1Data, Hash256, Slot};
use yaml_rust::yaml;

// Note: We Assume the block Id's are hex-encoded.

#[test]
fn test_bitwise_lmd_ghost() {
    // set up logging
    //Builder::from_env(Env::default().default_filter_or("trace")).init();

    test_yaml_vectors(
        ForkChoiceAlgorithm::BitwiseLMDGhost,
        "tests/bitwise_lmd_ghost_test_vectors.yaml",
        100,
    );
}

#[test]
fn test_slow_lmd_ghost() {
    test_yaml_vectors(
        ForkChoiceAlgorithm::SlowLMDGhost,
        "tests/lmd_ghost_test_vectors.yaml",
        100,
    );
}

#[test]
fn test_longest_chain() {
    test_yaml_vectors(
        ForkChoiceAlgorithm::LongestChain,
        "tests/longest_chain_test_vectors.yaml",
        100,
    );
}

// run a generic test over given YAML test vectors
fn test_yaml_vectors(
    fork_choice_algo: ForkChoiceAlgorithm,
    yaml_file_path: &str,
    emulated_validators: usize, // the number of validators used to give weights.
) {
    // load test cases from yaml
    let test_cases = load_test_cases_from_yaml(yaml_file_path);

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
        voluntary_exits: vec![],
        transfers: vec![],
    };

    // process the tests
    for test_case in test_cases {
        // setup a fresh test
        let (mut fork_choice, block_store, state_root) =
            setup_inital_state(&fork_choice_algo, emulated_validators);

        // keep a hashmap of block_id's to block_hashes (random hashes to abstract block_id)
        //let mut block_id_map: HashMap<String, Hash256> = HashMap::new();
        // keep a list of hash to slot
        let mut block_slot: HashMap<Hash256, Slot> = HashMap::new();
        // assume the block tree is given to us in order.
        let mut genesis_hash = None;
        for block in test_case["blocks"].clone().into_vec().unwrap() {
            let block_id = block["id"].as_str().unwrap().to_string();
            let parent_id = block["parent"].as_str().unwrap().to_string();

            // default params for genesis
            let block_hash = id_to_hash(&block_id);
            let mut slot = spec.genesis_slot;
            let parent_root = id_to_hash(&parent_id);

            // set the slot and parent based off the YAML. Start with genesis;
            // if not the genesis, update slot
            if parent_id != block_id {
                // find parent slot
                slot = *(block_slot
                    .get(&parent_root)
                    .expect("Parent should have a slot number"))
                    + 1;
            } else {
                genesis_hash = Some(block_hash);
            }

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

            // Store the block.
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
                let block_root = id_to_hash(&id.to_string());
                let weight = map_weight.as_i64().unwrap();
                // we assume a validator has a value 1 and add an attestation for to achieve the
                // correct weight
                for _ in 0..weight {
                    assert!(
                        current_validator <= emulated_validators,
                        "Not enough validators to emulate weights"
                    );
                    fork_choice
                        .add_attestation(current_validator as u64, &block_root, &spec)
                        .unwrap();
                    current_validator += 1;
                }
            }
        }

        // everything is set up, run the fork choice, using genesis as the head
        let head = fork_choice
            .find_head(&genesis_hash.unwrap(), &spec)
            .unwrap();

        // compare the result to the expected test
        let success = test_case["heads"]
            .clone()
            .into_vec()
            .unwrap()
            .iter()
            .find(|heads| id_to_hash(&heads["id"].as_str().unwrap().to_string()) == head)
            .is_some();

        println!("Head found: {}", head);
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
    fork_choice_algo: &ForkChoiceAlgorithm,
    no_validators: usize,
) -> (Box<ForkChoice>, Arc<BeaconBlockStore<MemoryDB>>, Hash256) {
    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    // the fork choice instantiation
    let fork_choice: Box<ForkChoice> = match fork_choice_algo {
        ForkChoiceAlgorithm::BitwiseLMDGhost => Box::new(BitwiseLMDGhost::new(
            block_store.clone(),
            state_store.clone(),
        )),
        ForkChoiceAlgorithm::SlowLMDGhost => {
            Box::new(SlowLMDGhost::new(block_store.clone(), state_store.clone()))
        }
        ForkChoiceAlgorithm::LongestChain => Box::new(LongestChain::new(block_store.clone())),
    };

    let spec = ChainSpec::foundation();

    let state_builder = TestingBeaconStateBuilder::new(no_validators, &spec);
    let (state, _keypairs) = state_builder.build();

    let state_root = state.canonical_root();
    state_store
        .put(&state_root, &ssz_encode(&state)[..])
        .unwrap();

    // return initialised vars
    (fork_choice, block_store, state_root)
}

// convert a block_id into a Hash256 -- assume input is hex encoded;
fn id_to_hash(id: &String) -> Hash256 {
    let bytes = hex::decode(id).expect("Block ID should be hex");

    let len = std::cmp::min(bytes.len(), 32);
    let mut fixed_bytes = [0u8; 32];
    for (index, byte) in bytes.iter().take(32).enumerate() {
        fixed_bytes[32 - len + index] = *byte;
    }
    Hash256::from(fixed_bytes)
}
