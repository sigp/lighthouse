use serde_derive::Deserialize;
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
fn yaml() {
    use serde_yaml;
    use std::{fs::File, io::prelude::*, path::PathBuf};

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
