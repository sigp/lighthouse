use super::*;
use std::{fs::File, io::prelude::*, path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct TestDoc {
    pub yaml: String,
}

impl TestDoc {
    fn new(path: PathBuf) -> Self {
        let mut file = File::open(path).unwrap();

        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();

        Self { yaml }
    }

    pub fn get_test_results(path: PathBuf) -> Vec<TestCaseResult> {
        let doc = Self::new(path);

        let header: TestDocHeader = serde_yaml::from_str(&doc.yaml.as_str()).unwrap();

        match (header.runner.as_ref(), header.handler.as_ref()) {
            ("ssz", "uint") => run_test::<SszGeneric>(&doc.yaml),
            (runner, handler) => panic!(
                "No implementation for runner {} handler {}",
                runner, handler
            ),
        }
    }

    pub fn assert_tests_pass(path: PathBuf) {
        let results = Self::get_test_results(path);

        let failures: Vec<&TestCaseResult> = results.iter().filter(|r| r.result.is_err()).collect();

        if !failures.is_empty() {
            panic!("{:?}", failures);
        }
    }
}

pub fn run_test<T>(test_doc_yaml: &String) -> Vec<TestCaseResult>
where
    TestDocCases<T>: Test + serde::de::DeserializeOwned,
{
    let doc: TestDocCases<T> = serde_yaml::from_str(&test_doc_yaml.as_str()).unwrap();

    doc.test()
}
