#![cfg(not(debug_assertions))]
/// Tests the available fork-choice algorithms
pub use beacon_chain::BeaconChain;
use bls::Signature;
use store::MemoryStore;
use store::Store;
// use env_logger::{Builder, Env};
use fork_choice::{BitwiseLMDGhost, ForkChoice, LongestChain, OptimizedLMDGhost, SlowLMDGhost};
use std::collections::HashMap;
use std::sync::Arc;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::test_utils::TestingBeaconStateBuilder;
use types::{
    BeaconBlock, BeaconBlockBody, Eth1Data, EthSpec, FoundationEthSpec, Hash256, Keypair, Slot,
};
use yaml_rust::yaml;

// Note: We Assume the block Id's are hex-encoded.

#[test]
fn test_optimized_lmd_ghost() {
    // set up logging
    // Builder::from_env(Env::default().default_filter_or("trace")).init();

    test_yaml_vectors::<OptimizedLMDGhost<MemoryStore, FoundationEthSpec>>(
        "tests/lmd_ghost_test_vectors.yaml",
        100,
    );
}

#[test]
fn test_bitwise_lmd_ghost() {
    // set up logging
    //Builder::from_env(Env::default().default_filter_or("trace")).init();

    test_yaml_vectors::<BitwiseLMDGhost<MemoryStore, FoundationEthSpec>>(
        "tests/bitwise_lmd_ghost_test_vectors.yaml",
        100,
    );
}

#[test]
fn test_slow_lmd_ghost() {
    test_yaml_vectors::<SlowLMDGhost<MemoryStore, FoundationEthSpec>>(
        "tests/lmd_ghost_test_vectors.yaml",
        100,
    );
}

#[test]
fn test_longest_chain() {
    test_yaml_vectors::<LongestChain<MemoryStore>>("tests/longest_chain_test_vectors.yaml", 100);
}

// run a generic test over given YAML test vectors
fn test_yaml_vectors<T: ForkChoice<MemoryStore>>(
    yaml_file_path: &str,
    emulated_validators: usize, // the number of validators used to give weights.
) {
    // load test cases from yaml
    let test_cases = load_test_cases_from_yaml(yaml_file_path);

    // default vars
    let spec = FoundationEthSpec::default_spec();
    let zero_hash = Hash256::zero();
    let eth1_data = Eth1Data {
        deposit_count: 0,
        deposit_root: zero_hash.clone(),
        block_hash: zero_hash.clone(),
    };
    let randao_reveal = Signature::empty_signature();
    let signature = Signature::empty_signature();
    let body = BeaconBlockBody {
        eth1_data,
        randao_reveal,
        graffiti: [0; 32],
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
        let (mut fork_choice, store, state_root) = setup_inital_state::<T>(emulated_validators);

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
            let previous_block_root = id_to_hash(&parent_id);

            // set the slot and parent based off the YAML. Start with genesis;
            // if not the genesis, update slot
            if parent_id != block_id {
                // find parent slot
                slot = *(block_slot
                    .get(&previous_block_root)
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
                previous_block_root,
                state_root: state_root.clone(),
                signature: signature.clone(),
                body: body.clone(),
            };

            // Store the block.
            store.put(&block_hash, &beacon_block).unwrap();

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

fn setup_inital_state<T>(
    // fork_choice_algo: &ForkChoiceAlgorithm,
    num_validators: usize
) -> (T, Arc<MemoryStore>, Hash256)
where
    T: ForkChoice<MemoryStore>,
{
    let store = Arc::new(MemoryStore::open());

    let fork_choice = ForkChoice::new(store.clone());
    let spec = FoundationEthSpec::default_spec();

    let mut state_builder: TestingBeaconStateBuilder<FoundationEthSpec> =
        TestingBeaconStateBuilder::from_single_keypair(num_validators, &Keypair::random(), &spec);
    state_builder.build_caches(&spec).unwrap();
    let (state, _keypairs) = state_builder.build();

    let state_root = state.canonical_root();
    store.put(&state_root, &state).unwrap();

    // return initialised vars
    (fork_choice, store, state_root)
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
