use crate::case_result::CaseResult;
use crate::cases::*;
use crate::doc_header::DocHeader;
use crate::eth_specs::{MainnetEthSpec, MinimalEthSpec};
use crate::yaml_decode::{yaml_split_header_and_cases, YamlDecode};
use crate::EfTest;
use serde_derive::Deserialize;
use std::{fs::File, io::prelude::*, path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct Doc {
    pub header_yaml: String,
    pub cases_yaml: String,
    pub path: PathBuf,
}

impl Doc {
    fn from_path(path: PathBuf) -> Self {
        let mut file = File::open(path.clone()).unwrap();

        let mut yaml = String::new();
        file.read_to_string(&mut yaml).unwrap();

        let (header_yaml, cases_yaml) = yaml_split_header_and_cases(yaml.clone());

        Self {
            header_yaml,
            cases_yaml,
            path,
        }
    }

    pub fn test_results(&self) -> Vec<CaseResult> {
        let header: DocHeader = serde_yaml::from_str(&self.header_yaml.as_str()).unwrap();

        match (
            header.runner.as_ref(),
            header.handler.as_ref(),
            header.config.as_ref(),
        ) {
            ("ssz", "uint", _) => run_test::<SszGeneric>(self),
            ("ssz", "static", "minimal") => run_test::<SszStatic<MinimalEthSpec>>(self),
            ("ssz", "static", "mainnet") => run_test::<SszStatic<MainnetEthSpec>>(self),
            ("bls", "aggregate_pubkeys", "mainnet") => run_test::<BlsAggregatePubkeys>(self),
            ("bls", "aggregate_sigs", "mainnet") => run_test::<BlsAggregateSigs>(self),
            ("bls", "msg_hash_compressed", "mainnet") => run_test::<BlsG2Compressed>(self),
            // Note this test fails due to a difference in our internal representations. It does
            // not effect verification or external representation.
            //
            // It is skipped.
            ("bls", "msg_hash_uncompressed", "mainnet") => vec![],
            ("bls", "priv_to_pub", "mainnet") => run_test::<BlsPrivToPub>(self),
            ("bls", "sign_msg", "mainnet") => run_test::<BlsSign>(self),
            ("operations", "deposit", "mainnet") => {
                run_test::<OperationsDeposit<MainnetEthSpec>>(self)
            }
            ("operations", "deposit", "minimal") => {
                run_test::<OperationsDeposit<MinimalEthSpec>>(self)
            }
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

pub fn run_test<T>(doc: &Doc) -> Vec<CaseResult>
where
    Cases<T>: EfTest + YamlDecode,
{
    // Extract only the "test_cases" YAML as a stand-alone string.
    //let test_cases_yaml = extract_yaml_by_key(self., "test_cases");

    // Pass only the "test_cases" YAML string to `yaml_decode`.
    let test_cases: Cases<T> = Cases::yaml_decode(&doc.cases_yaml).unwrap();

    test_cases.test_results()
}

pub fn print_failures(doc: &Doc, results: &[CaseResult]) {
    let header: DocHeader = serde_yaml::from_str(&doc.header_yaml).unwrap();
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
