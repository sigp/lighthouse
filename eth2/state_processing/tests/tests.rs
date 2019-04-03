use serde_derive::Deserialize;
use serde_yaml;
#[cfg(not(debug_assertions))]
use state_processing::{per_block_processing, per_slot_processing};
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::*;

#[derive(Debug, Deserialize)]
pub struct ExpectedState {
    pub slot: Option<Slot>,
    pub genesis_time: Option<u64>,
    pub fork: Option<Fork>,
    pub validator_registry: Option<Vec<Validator>>,
    pub validator_balances: Option<Vec<u64>>,
    pub previous_epoch_attestations: Option<Vec<PendingAttestation>>,
    pub current_epoch_attestations: Option<Vec<PendingAttestation>>,
    pub historical_roots: Option<Vec<Hash256>>,
    pub finalized_epoch: Option<Epoch>,
    pub latest_block_roots: Option<Vec<Hash256>>,
}

impl ExpectedState {
    // Return a list of fields that differ, and a string representation of the beacon state's field.
    fn check(&self, state: &BeaconState) -> Vec<(&str, String)> {
        // Check field equality
        macro_rules! cfe {
            ($field_name:ident) => {
                if self.$field_name.as_ref().map_or(true, |$field_name| {
                    println!("  > Checking {}", stringify!($field_name));
                    $field_name == &state.$field_name
                }) {
                    vec![]
                } else {
                    vec![(stringify!($field_name), format!("{:#?}", state.$field_name))]
                }
            };
        }

        vec![
            cfe!(slot),
            cfe!(genesis_time),
            cfe!(fork),
            cfe!(validator_registry),
            cfe!(validator_balances),
            cfe!(previous_epoch_attestations),
            cfe!(current_epoch_attestations),
            cfe!(historical_roots),
            cfe!(finalized_epoch),
            cfe!(latest_block_roots),
        ]
        .into_iter()
        .flat_map(|x| x)
        .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub config: ChainSpec,
    pub verify_signatures: bool,
    pub initial_state: BeaconState,
    pub blocks: Vec<BeaconBlock>,
    pub expected_state: ExpectedState,
}

#[derive(Debug, Deserialize)]
pub struct TestDoc {
    pub title: String,
    pub summary: String,
    pub fork: String,
    pub test_cases: Vec<TestCase>,
}

fn load_test_case(test_name: &str) -> TestDoc {
    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push(format!("yaml_utils/specs/{}", test_name));

        File::open(file_path_buf).unwrap()
    };
    let mut yaml_str = String::new();
    file.read_to_string(&mut yaml_str).unwrap();
    yaml_str = yaml_str.to_lowercase();

    serde_yaml::from_str(&yaml_str.as_str()).unwrap()
}

fn run_state_transition_test(test_name: &str) {
    let doc = load_test_case(test_name);

    // Run Tests
    let mut ok = true;
    for (i, test_case) in doc.test_cases.iter().enumerate() {
        let fake_crypto = cfg!(feature = "fake_crypto");
        if !test_case.verify_signatures == fake_crypto {
            println!("Running {}", test_case.name);
        } else {
            println!(
                "Skipping {} (fake_crypto: {}, need fake: {})",
                test_case.name, fake_crypto, !test_case.verify_signatures
            );
            continue;
        }
        let mut state = test_case.initial_state.clone();
        for (j, block) in test_case.blocks.iter().enumerate() {
            while block.slot > state.slot {
                let latest_block_header = state.latest_block_header.clone();
                per_slot_processing(&mut state, &latest_block_header, &test_case.config).unwrap();
            }
            let res = per_block_processing(&mut state, &block, &test_case.config);
            if res.is_err() {
                println!("Error in {} (#{}), on block {}", test_case.name, i, j);
                println!("{:?}", res);
                ok = false;
            }
        }

        let mismatched_fields = test_case.expected_state.check(&state);
        if !mismatched_fields.is_empty() {
            println!(
                "Error in expected state, these fields didn't match: {:?}",
                mismatched_fields.iter().map(|(f, _)| f).collect::<Vec<_>>()
            );
            for (field_name, state_val) in mismatched_fields {
                println!("state.{} was: {}", field_name, state_val);
            }
            ok = false;
        }
    }

    assert!(ok, "one or more tests failed, see above");
}

#[test]
#[cfg(not(debug_assertions))]
fn test_read_yaml() {
    load_test_case("sanity-check_small-config_32-vals.yaml");
    load_test_case("sanity-check_default-config_100-vals.yaml");
}

#[test]
#[cfg(not(debug_assertions))]
fn run_state_transition_tests_small() {
    run_state_transition_test("sanity-check_small-config_32-vals.yaml");
}

#[test]
#[cfg(not(debug_assertions))]
fn run_state_transition_tests_large() {
    run_state_transition_test("sanity-check_default-config_100-vals.yaml");
}
