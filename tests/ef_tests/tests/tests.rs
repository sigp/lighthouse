use ef_tests::*;
use serde::de::DeserializeOwned;
use std::{fs::File, io::prelude::*, path::PathBuf};

fn load_test_case<T: DeserializeOwned>(test_name: &str) -> TestDoc<T> {
    let mut file = {
        let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path_buf.push(format!("eth2.0-spec-tests/tests/{}", test_name));

        File::open(file_path_buf).unwrap()
    };

    let mut yaml_str = String::new();
    file.read_to_string(&mut yaml_str).unwrap();
    yaml_str = yaml_str.to_lowercase();

    serde_yaml::from_str(&yaml_str.as_str()).unwrap()
}

#[test]
fn ssz() {
    let doc: TestDoc<SszGeneric> = load_test_case("ssz_generic/uint/uint_bounds.yaml");

    let results = doc.test();

    let failures: Vec<&TestCaseResult<SszGeneric>> =
        results.iter().filter(|r| r.result.is_err()).collect();

    if !failures.is_empty() {
        panic!("{:?}", failures);
    }
}
