use serde_derive::Deserialize;
use types::*;

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
    pub version: String,
    pub test_cases: Vec<TestCase>,
}

#[test]
fn yaml() {
    use serde_yaml;
    use std::{fs::File, io::prelude::*, path::PathBuf};

    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push("specs/example.yml");

        File::open(file_path_buf).unwrap()
    };

    let mut yaml_str = String::new();

    file.read_to_string(&mut yaml_str).unwrap();

    let yaml_str = yaml_str.to_lowercase();

    let _doc: TestDoc = serde_yaml::from_str(&yaml_str.as_str()).unwrap();
}
