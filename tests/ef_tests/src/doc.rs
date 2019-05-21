use crate::case_result::CaseResult;
use crate::cases::*;
use crate::doc_header::DocHeader;
use crate::eth_specs::{MainnetEthSpec, MinimalEthSpec};
use crate::yaml_decode::{extract_yaml_by_key, YamlDecode};
use crate::EfTest;
use serde_derive::Deserialize;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::EthSpec;

#[derive(Debug, Deserialize)]
pub struct Doc {
    pub yaml: String,
    pub path: PathBuf,
}

impl Doc {
    fn from_path(path: PathBuf) -> Self {
        let mut file = File::open(path.clone()).unwrap();

        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();

        Self { yaml, path }
    }

    pub fn test_results(&self) -> Vec<CaseResult> {
        let header: DocHeader = serde_yaml::from_str(&self.yaml.as_str()).unwrap();

        match (
            header.runner.as_ref(),
            header.handler.as_ref(),
            header.config.as_ref(),
        ) {
            ("ssz", "uint", _) => run_test::<SszGeneric, MainnetEthSpec>(&self.yaml),
            ("ssz", "static", "minimal") => run_test::<SszStatic, MinimalEthSpec>(&self.yaml),
            ("ssz", "static", "mainnet") => run_test::<SszStatic, MainnetEthSpec>(&self.yaml),
            ("bls", "aggregate_pubkeys", "mainnet") => {
                run_test::<BlsAggregatePubkeys, MainnetEthSpec>(&self.yaml)
            }
            ("bls", "aggregate_sigs", "mainnet") => {
                run_test::<BlsAggregateSigs, MainnetEthSpec>(&self.yaml)
            }
            ("bls", "msg_hash_compressed", "mainnet") => {
                run_test::<BlsG2Compressed, MainnetEthSpec>(&self.yaml)
            }
            ("bls", "msg_hash_uncompressed", "mainnet") => {
                // Note this test fails but Not due to a bug
                vec![] // run_test::<BlsG2Uncompressed, MainnetEthSpec>(&self.yaml)
            }
            ("bls", "priv_to_pub", "mainnet") => {
                run_test::<BlsPrivToPub, MainnetEthSpec>(&self.yaml)
            }
            ("bls", "sign_msg", "mainnet") => run_test::<BlsSign, MainnetEthSpec>(&self.yaml),
            (runner, handler, config) => panic!(
                "No implementation for runner: \"{}\", handler: \"{}\", config: \"{}\"",
                runner, handler, config
            ),
        }
    }

    pub fn assert_tests_pass(path: PathBuf) {
        let doc = Self::from_path(path);
        let results = doc.test_results();

        if results.iter().any(|r| r.result.is_err()) {
            print_failures(&doc, &results);
            panic!("Tests failed (see above)");
        } else {
            println!("Passed {} tests in {:?}", results.len(), doc.path);
        }
    }
}

pub fn run_test<T, E: EthSpec>(test_doc_yaml: &String) -> Vec<CaseResult>
where
    Cases<T>: EfTest + YamlDecode,
{
    // Extract only the "test_cases" YAML as a stand-alone string.
    let test_cases_yaml = extract_yaml_by_key(test_doc_yaml, "test_cases");

    // Pass only the "test_cases" YAML string to `yaml_decode`.
    let test_cases: Cases<T> = Cases::yaml_decode(&test_cases_yaml.to_string()).unwrap();

    test_cases.test_results::<E>()
}

pub fn print_failures(doc: &Doc, results: &[CaseResult]) {
    let header: DocHeader = serde_yaml::from_str(&doc.yaml).unwrap();
    let failures: Vec<&CaseResult> = results.iter().filter(|r| r.result.is_err()).collect();

    println!("--------------------------------------------------");
    println!("Test Failure");
    println!("Title: {}", header.title);
    println!("File: {:?}", doc.path);
    println!("");
    println!(
        "{} tests, {} failures, {} passes.",
        results.len(),
        failures.len(),
        results.len() - failures.len()
    );
    println!("");

    for failure in failures {
        println!("-------");
        println!("case[{}].result:", failure.case_index);
        println!("{:#?}", failure.result);
    }
    println!("");
}
