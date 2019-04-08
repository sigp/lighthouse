use serde_derive::Deserialize;
use serde_yaml;
#[cfg(not(debug_assertions))]
use state_processing::{
    per_block_processing, per_block_processing_without_verifying_block_signature,
    per_slot_processing,
};
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::*;
#[allow(unused_imports)]
use yaml_utils;

#[derive(Debug, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub config: ChainSpec,
    pub verify_signatures: bool,
    pub initial_state: BeaconState,
    pub blocks: Vec<BeaconBlock>,
}

#[derive(Debug, Deserialize)]
pub struct TestDoc {
    pub title: String,
    pub summary: String,
    pub fork: String,
    pub test_cases: Vec<TestCase>,
}

#[test]
fn test_read_yaml() {
    // Test sanity-check_small-config_32-vals.yaml
    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push("yaml_utils/specs/sanity-check_small-config_32-vals.yaml");

        File::open(file_path_buf).unwrap()
    };

    let mut yaml_str = String::new();

    file.read_to_string(&mut yaml_str).unwrap();

    yaml_str = yaml_str.to_lowercase();

    let _doc: TestDoc = serde_yaml::from_str(&yaml_str.as_str()).unwrap();

    // Test sanity-check_default-config_100-vals.yaml
    file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push("yaml_utils/specs/sanity-check_default-config_100-vals.yaml");

        File::open(file_path_buf).unwrap()
    };

    yaml_str = String::new();

    file.read_to_string(&mut yaml_str).unwrap();

    yaml_str = yaml_str.to_lowercase();

    let _doc: TestDoc = serde_yaml::from_str(&yaml_str.as_str()).unwrap();
}

#[test]
#[cfg(not(debug_assertions))]
fn run_state_transition_tests_small() {
    // Test sanity-check_small-config_32-vals.yaml
    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push("yaml_utils/specs/sanity-check_small-config_32-vals.yaml");

        File::open(file_path_buf).unwrap()
    };
    let mut yaml_str = String::new();
    file.read_to_string(&mut yaml_str).unwrap();
    yaml_str = yaml_str.to_lowercase();

    let doc: TestDoc = serde_yaml::from_str(&yaml_str.as_str()).unwrap();

    // Run Tests
    for (i, test_case) in doc.test_cases.iter().enumerate() {
        let mut state = test_case.initial_state.clone();
        for block in test_case.blocks.iter() {
            while block.slot > state.slot {
                let latest_block_header = state.latest_block_header.clone();
                per_slot_processing(&mut state, &latest_block_header, &test_case.config).unwrap();
            }
            if test_case.verify_signatures {
                let res = per_block_processing(&mut state, &block, &test_case.config);
                if res.is_err() {
                    println!("{:?}", i);
                    println!("{:?}", res);
                };
            } else {
                let res = per_block_processing_without_verifying_block_signature(
                    &mut state,
                    &block,
                    &test_case.config,
                );
                if res.is_err() {
                    println!("{:?}", i);
                    println!("{:?}", res);
                }
            }
        }
    }
}
