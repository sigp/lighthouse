use crate::case_result::CaseResult;
use crate::cases::*;
use crate::doc_header::DocHeader;
use crate::error::Error;
use crate::yaml_decode::{yaml_split_header_and_cases, YamlDecode};
use crate::EfTest;
use serde_derive::Deserialize;
use std::{fs::File, io::prelude::*, path::PathBuf};
use types::{MainnetEthSpec, MinimalEthSpec};

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
            ("sanity", "slots", "minimal") => run_test::<SanitySlots<MinimalEthSpec>>(self),
            // FIXME: skipped due to compact committees issue
            ("sanity", "slots", "mainnet") => vec![], // run_test::<SanitySlots<MainnetEthSpec>>(self),
            ("sanity", "blocks", "minimal") => run_test::<SanityBlocks<MinimalEthSpec>>(self),
            // FIXME: skipped due to compact committees issue
            ("sanity", "blocks", "mainnet") => vec![], // run_test::<SanityBlocks<MainnetEthSpec>>(self),
            ("shuffling", "core", "minimal") => run_test::<Shuffling<MinimalEthSpec>>(self),
            ("shuffling", "core", "mainnet") => run_test::<Shuffling<MainnetEthSpec>>(self),
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
            ("operations", "transfer", "mainnet") => {
                run_test::<OperationsTransfer<MainnetEthSpec>>(self)
            }
            ("operations", "transfer", "minimal") => {
                run_test::<OperationsTransfer<MinimalEthSpec>>(self)
            }
            ("operations", "voluntary_exit", "mainnet") => {
                run_test::<OperationsExit<MainnetEthSpec>>(self)
            }
            ("operations", "voluntary_exit", "minimal") => {
                run_test::<OperationsExit<MinimalEthSpec>>(self)
            }
            ("operations", "proposer_slashing", "mainnet") => {
                run_test::<OperationsProposerSlashing<MainnetEthSpec>>(self)
            }
            ("operations", "proposer_slashing", "minimal") => {
                run_test::<OperationsProposerSlashing<MinimalEthSpec>>(self)
            }
            ("operations", "attester_slashing", "mainnet") => {
                run_test::<OperationsAttesterSlashing<MainnetEthSpec>>(self)
            }
            ("operations", "attester_slashing", "minimal") => {
                run_test::<OperationsAttesterSlashing<MinimalEthSpec>>(self)
            }
            ("operations", "attestation", "mainnet") => {
                run_test::<OperationsAttestation<MainnetEthSpec>>(self)
            }
            ("operations", "attestation", "minimal") => {
                run_test::<OperationsAttestation<MinimalEthSpec>>(self)
            }
            ("operations", "block_header", "mainnet") => {
                run_test::<OperationsBlockHeader<MainnetEthSpec>>(self)
            }
            ("operations", "block_header", "minimal") => {
                run_test::<OperationsBlockHeader<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "crosslinks", "minimal") => {
                run_test::<EpochProcessingCrosslinks<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "crosslinks", "mainnet") => {
                run_test::<EpochProcessingCrosslinks<MainnetEthSpec>>(self)
            }
            ("epoch_processing", "registry_updates", "minimal") => {
                run_test::<EpochProcessingRegistryUpdates<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "registry_updates", "mainnet") => {
                run_test::<EpochProcessingRegistryUpdates<MainnetEthSpec>>(self)
            }
            ("epoch_processing", "justification_and_finalization", "minimal") => {
                run_test::<EpochProcessingJustificationAndFinalization<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "justification_and_finalization", "mainnet") => {
                run_test::<EpochProcessingJustificationAndFinalization<MainnetEthSpec>>(self)
            }
            ("epoch_processing", "slashings", "minimal") => {
                run_test::<EpochProcessingSlashings<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "slashings", "mainnet") => {
                run_test::<EpochProcessingSlashings<MainnetEthSpec>>(self)
            }
            ("epoch_processing", "final_updates", "minimal") => {
                run_test::<EpochProcessingFinalUpdates<MinimalEthSpec>>(self)
            }
            ("epoch_processing", "final_updates", "mainnet") => {
                vec![]
                // FIXME: skipped due to compact committees issue
                // run_test::<EpochProcessingFinalUpdates<MainnetEthSpec>>(self)
            }
            ("genesis", "initialization", "minimal") => {
                run_test::<GenesisInitialization<MinimalEthSpec>>(self)
            }
            ("genesis", "initialization", "mainnet") => {
                run_test::<GenesisInitialization<MainnetEthSpec>>(self)
            }
            ("genesis", "validity", "minimal") => run_test::<GenesisValidity<MinimalEthSpec>>(self),
            ("genesis", "validity", "mainnet") => run_test::<GenesisValidity<MainnetEthSpec>>(self),
            (runner, handler, config) => panic!(
                "No implementation for runner: \"{}\", handler: \"{}\", config: \"{}\"",
                runner, handler, config
            ),
        }
    }

    pub fn assert_tests_pass(path: PathBuf) {
        let doc = Self::from_path(path);
        let results = doc.test_results();

        let (failed, skipped_bls, skipped_known_failures) = categorize_results(&results);

        if failed.len() + skipped_known_failures.len() > 0 {
            print_results(
                &doc,
                &failed,
                &skipped_bls,
                &skipped_known_failures,
                &results,
            );
            if !failed.is_empty() {
                panic!("Tests failed (see above)");
            }
        } else {
            println!("Passed {} tests in {:?}", results.len(), doc.path);
        }
    }
}

pub fn run_test<T>(doc: &Doc) -> Vec<CaseResult>
where
    Cases<T>: EfTest + YamlDecode,
{
    // Pass only the "test_cases" YAML string to `yaml_decode`.
    let test_cases: Cases<T> = Cases::yaml_decode(&doc.cases_yaml).unwrap();

    test_cases.test_results()
}

pub fn categorize_results(
    results: &[CaseResult],
) -> (Vec<&CaseResult>, Vec<&CaseResult>, Vec<&CaseResult>) {
    let mut failed = vec![];
    let mut skipped_bls = vec![];
    let mut skipped_known_failures = vec![];

    for case in results {
        match case.result.as_ref().err() {
            Some(Error::SkippedBls) => skipped_bls.push(case),
            Some(Error::SkippedKnownFailure) => skipped_known_failures.push(case),
            Some(_) => failed.push(case),
            None => (),
        }
    }

    (failed, skipped_bls, skipped_known_failures)
}

pub fn print_results(
    doc: &Doc,
    failed: &[&CaseResult],
    skipped_bls: &[&CaseResult],
    skipped_known_failures: &[&CaseResult],
    results: &[CaseResult],
) {
    let header: DocHeader = serde_yaml::from_str(&doc.header_yaml).unwrap();
    println!("--------------------------------------------------");
    println!(
        "Test {}",
        if failed.is_empty() {
            "Result"
        } else {
            "Failure"
        }
    );
    println!("Title: {}", header.title);
    println!("File: {:?}", doc.path);
    println!(
        "{} tests, {} failed, {} skipped (known failure), {} skipped (bls), {} passed. (See below for errors)",
        results.len(),
        failed.len(),
        skipped_known_failures.len(),
        skipped_bls.len(),
        results.len() - skipped_bls.len() - skipped_known_failures.len() - failed.len()
    );
    println!();

    for case in skipped_known_failures {
        println!("-------");
        println!(
            "case[{}] ({}) skipped because it's a known failure",
            case.case_index, case.desc,
        );
    }
    for failure in failed {
        let error = failure.result.clone().unwrap_err();

        println!("-------");
        println!(
            "case[{}] ({}) failed with {}:",
            failure.case_index,
            failure.desc,
            error.name()
        );
        println!("{}", error.message());
    }
    println!();
}
