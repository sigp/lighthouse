use super::*;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::{EthSpec, FoundationEthSpec};

#[derive(Debug, Deserialize)]
pub struct TestDoc {
    pub yaml: String,
}

impl TestDoc {
    fn from_path(path: PathBuf) -> Self {
        let mut file = File::open(path).unwrap();

        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();

        Self { yaml }
    }

    pub fn get_test_results(path: PathBuf) -> Vec<TestCaseResult> {
        let doc = Self::from_path(path);

        let header: TestDocHeader = serde_yaml::from_str(&doc.yaml.as_str()).unwrap();

        match (
            header.runner.as_ref(),
            header.handler.as_ref(),
            header.config.as_ref(),
        ) {
            ("ssz", "uint", _) => run_test::<SszGeneric, FoundationEthSpec>(&doc.yaml),
            ("ssz", "static", "minimal") => run_test::<SszStatic, MinimalEthSpec>(&doc.yaml),
            (runner, handler, config) => panic!(
                "No implementation for runner: \"{}\", handler: \"{}\", config: \"{}\"",
                runner, handler, config
            ),
        }
    }

    pub fn assert_tests_pass(path: PathBuf) {
        let results = Self::get_test_results(path);

        let failures: Vec<&TestCaseResult> = results.iter().filter(|r| r.result.is_err()).collect();

        if !failures.is_empty() {
            for f in &failures {
                dbg!(&f.case_index);
                dbg!(&f.result);
            }
            panic!("{}/{} tests failed.", failures.len(), results.len())
        }
    }
}

pub fn run_test<T, E: EthSpec>(test_doc_yaml: &String) -> Vec<TestCaseResult>
where
    TestDocCases<T>: Test + serde::de::DeserializeOwned + TestDecode,
{
    let test_cases_yaml = extract_yaml_by_key(test_doc_yaml, "test_cases");

    let test_cases: TestDocCases<T> =
        TestDocCases::test_decode(&test_cases_yaml.to_string()).unwrap();

    test_cases.test::<E>()
}
