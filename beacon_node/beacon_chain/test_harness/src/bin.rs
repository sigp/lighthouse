use self::beacon_chain_harness::BeaconChainHarness;
use self::validator_harness::ValidatorHarness;
use beacon_chain::CheckPoint;
use clap::{App, Arg};
use env_logger::{Builder, Env};
use log::{info, warn};
use std::collections::HashMap;
use std::{fs::File, io::prelude::*};
use types::*;
use yaml_rust::{Yaml, YamlLoader};

mod beacon_chain_harness;
mod validator_harness;

fn main() {
    let matches = App::new("Lighthouse Test Harness Runner")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Runs `test_harness` using a YAML manifest.")
        .arg(
            Arg::with_name("yaml")
                .long("yaml")
                .value_name("FILE")
                .help("YAML file manifest.")
                .required(true),
        )
        .get_matches();

    Builder::from_env(Env::default().default_filter_or("debug")).init();

    if let Some(yaml_file) = matches.value_of("yaml") {
        let docs = {
            let mut file = File::open(yaml_file).unwrap();

            let mut yaml_str = String::new();
            file.read_to_string(&mut yaml_str).unwrap();

            YamlLoader::load_from_str(&yaml_str).unwrap()
        };

        for doc in &docs {
            for test_case in doc["test_cases"].as_vec().unwrap() {
                let manifest = Manifest::from_yaml(test_case);
                manifest.assert_result_valid(manifest.execute())
            }
        }
    }
}

struct Manifest {
    pub results: Results,
    pub config: Config,
}

impl Manifest {
    pub fn from_yaml(test_case: &Yaml) -> Self {
        Self {
            results: Results::from_yaml(&test_case["results"]),
            config: Config::from_yaml(&test_case["config"]),
        }
    }

    fn spec(&self) -> ChainSpec {
        let mut spec = ChainSpec::foundation();

        if let Some(n) = self.config.epoch_length {
            spec.epoch_length = n;
        }

        spec
    }

    pub fn execute(&self) -> ExecutionResult {
        let spec = self.spec();
        let validator_count = self.config.deposits_for_chain_start;
        let slots = self.results.slot;

        info!(
            "Building BeaconChainHarness with {} validators...",
            validator_count
        );

        let mut harness = BeaconChainHarness::new(spec, validator_count);

        info!("Starting simulation across {} slots...", slots);

        for slot_height in 0..self.results.slot {
            match self.config.skip_slots {
                Some(ref skip_slots) if skip_slots.contains(&slot_height) => {
                    warn!("Skipping slot at height {}.", slot_height);
                    harness.increment_beacon_chain_slot();
                }
                _ => {
                    info!("Producing block at slot height {}.", slot_height);
                    harness.advance_chain_with_block();
                }
            }
        }

        harness.run_fork_choice();

        info!("Test execution complete!");

        ExecutionResult {
            chain: harness.chain_dump().expect("Chain dump failed."),
        }
    }

    pub fn assert_result_valid(&self, result: ExecutionResult) {
        info!("Verifying test results...");

        if let Some(ref skip_slots) = self.config.skip_slots {
            for checkpoint in result.chain {
                let block_slot = checkpoint.beacon_block.slot.as_u64();
                assert!(
                    !skip_slots.contains(&block_slot),
                    "Slot {} was not skipped.",
                    block_slot
                );
            }
        }
        info!("OK: Skipped slots not present in chain.");
    }
}

struct ExecutionResult {
    pub chain: Vec<CheckPoint>,
}

struct Results {
    pub slot: u64,
    pub num_validators: Option<usize>,
    pub slashed_validators: Option<Vec<u64>>,
    pub exited_validators: Option<Vec<u64>>,
}

impl Results {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            slot: as_u64(&yaml, "slot").expect("Must have end slot"),
            num_validators: as_usize(&yaml, "num_validators"),
            slashed_validators: as_vec_u64(&yaml, "slashed_validators"),
            exited_validators: as_vec_u64(&yaml, "exited_validators"),
        }
    }
}

struct Config {
    pub deposits_for_chain_start: usize,
    pub epoch_length: Option<u64>,
    pub skip_slots: Option<Vec<u64>>,
}

impl Config {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            deposits_for_chain_start: as_usize(&yaml, "deposits_for_chain_start")
                .expect("Must specify validator count"),
            epoch_length: as_u64(&yaml, "epoch_length"),
            skip_slots: as_vec_u64(yaml, "skip_slots"),
        }
    }
}

fn as_usize(yaml: &Yaml, key: &str) -> Option<usize> {
    yaml[key].as_i64().and_then(|n| Some(n as usize))
}

fn as_u64(yaml: &Yaml, key: &str) -> Option<u64> {
    yaml[key].as_i64().and_then(|n| Some(n as u64))
}

fn as_vec_u64(yaml: &Yaml, key: &str) -> Option<Vec<u64>> {
    yaml[key].clone().into_vec().and_then(|vec| {
        Some(
            vec.iter()
                .map(|item| item.as_i64().unwrap() as u64)
                .collect(),
        )
    })
}
