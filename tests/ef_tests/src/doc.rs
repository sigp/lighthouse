use crate::case_result::CaseResult;
use crate::cases::*;
use crate::doc_header::DocHeader;
use crate::eth_specs::MinimalEthSpec;
use crate::yaml_decode::{extract_yaml_by_key, YamlDecode};
use crate::EfTest;
use serde_derive::Deserialize;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::{EthSpec, FoundationEthSpec};

#[derive(Debug, Deserialize)]
pub struct Doc {
    pub yaml: String,
}

impl Doc {
    fn from_path(path: PathBuf) -> Self {
        let mut file = File::open(path).unwrap();

        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();

        Self { yaml }
    }

    pub fn get_test_results(path: PathBuf) -> Vec<CaseResult> {
        let doc = Self::from_path(path);

        let header: DocHeader = serde_yaml::from_str(&doc.yaml.as_str()).unwrap();

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

        let failures: Vec<&CaseResult> = results.iter().filter(|r| r.result.is_err()).collect();

        if !failures.is_empty() {
            for f in &failures {
                dbg!(&f.case_index);
                dbg!(&f.result);
            }
            panic!("{}/{} tests failed.", failures.len(), results.len())
        }
    }
}

pub fn run_test<T, E: EthSpec>(test_doc_yaml: &String) -> Vec<CaseResult>
where
    Cases<T>: EfTest + serde::de::DeserializeOwned + YamlDecode,
{
    let test_cases_yaml = extract_yaml_by_key(test_doc_yaml, "test_cases");

    let test_cases: Cases<T> = Cases::yaml_decode(&test_cases_yaml.to_string()).unwrap();

    test_cases.test_results::<E>()
}
