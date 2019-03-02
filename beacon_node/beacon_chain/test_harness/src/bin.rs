use self::beacon_chain_harness::BeaconChainHarness;
use self::validator_harness::ValidatorHarness;
use beacon_chain::CheckPoint;
use bls::create_proof_of_possession;
use clap::{App, Arg};
use env_logger::{Builder, Env};
use log::{info, warn};
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
        let slots = self.config.num_slots;

        info!(
            "Building BeaconChainHarness with {} validators...",
            validator_count
        );

        let mut harness = BeaconChainHarness::new(spec, validator_count);

        info!("Starting simulation across {} slots...", slots);

        for slot_height in 0..slots {
            // Feed deposits to the BeaconChain.
            if let Some(ref deposits) = self.config.deposits {
                for (slot, deposit, keypair) in deposits {
                    if *slot == slot_height {
                        info!("Including deposit at slot height {}.", slot_height);
                        harness.add_deposit(deposit.clone(), Some(keypair.clone()));
                    }
                }
            }

            // Feed proposer slashings to the BeaconChain.
            if let Some(ref slashings) = self.config.proposer_slashings {
                for (slot, slashing) in slashings {
                    if *slot == slot_height {
                        info!(
                            "Including proposer slashing at slot height {}.",
                            slot_height
                        );
                        harness.add_proposer_slashing(slashing.clone());
                    }
                }
            }

            // Build a block or skip a slot.
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

        let skipped_slots = self
            .config
            .skip_slots
            .clone()
            .and_then(|slots| Some(slots.len()))
            .unwrap_or_else(|| 0);
        let expected_blocks = self.config.num_slots as usize + 1 - skipped_slots;

        assert_eq!(result.chain.len(), expected_blocks);

        info!(
            "OK: Chain length is {} ({} skipped slots).",
            result.chain.len(),
            skipped_slots
        );

        if let Some(ref skip_slots) = self.config.skip_slots {
            for checkpoint in &result.chain {
                let block_slot = checkpoint.beacon_block.slot.as_u64();
                assert!(
                    !skip_slots.contains(&block_slot),
                    "Slot {} was not skipped.",
                    block_slot
                );
            }
            info!("OK: Skipped slots not present in chain.");
        }

        if let Some(ref deposits) = self.config.deposits {
            let latest_state = &result.chain.last().expect("Empty chain.").beacon_state;
            assert_eq!(
                latest_state.validator_registry.len(),
                self.config.deposits_for_chain_start + deposits.len()
            );
            info!(
                "OK: Validator registry has {} more validators.",
                deposits.len()
            );
        }
    }
}

pub type DepositTuple = (u64, Deposit, Keypair);
pub type ProposerSlashingTuple = (u64, ProposerSlashing);

struct ExecutionResult {
    pub chain: Vec<CheckPoint>,
}

struct Results {
    pub num_validators: Option<usize>,
    pub slashed_validators: Option<Vec<u64>>,
    pub exited_validators: Option<Vec<u64>>,
}

impl Results {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            num_validators: as_usize(&yaml, "num_validators"),
            slashed_validators: as_vec_u64(&yaml, "slashed_validators"),
            exited_validators: as_vec_u64(&yaml, "exited_validators"),
        }
    }
}

struct Config {
    pub deposits_for_chain_start: usize,
    pub epoch_length: Option<u64>,
    pub num_slots: u64,
    pub skip_slots: Option<Vec<u64>>,
    pub deposits: Option<Vec<DepositTuple>>,
    pub proposer_slashings: Option<Vec<ProposerSlashingTuple>>,
}

impl Config {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            deposits_for_chain_start: as_usize(&yaml, "deposits_for_chain_start")
                .expect("Must specify validator count"),
            epoch_length: as_u64(&yaml, "epoch_length"),
            num_slots: as_u64(&yaml, "num_slots").expect("Must specify `config.num_slots`"),
            skip_slots: as_vec_u64(yaml, "skip_slots"),
            deposits: parse_deposits(&yaml),
            proposer_slashings: parse_proposer_slashings(&yaml),
        }
    }
}

fn parse_proposer_slashings(yaml: &Yaml) -> Option<Vec<ProposerSlashingTuple>> {
    let mut slashings = vec![];

    for slashing in yaml["proposer_slashings"].as_vec()? {
        let slot = as_u64(slashing, "slot").expect("Incomplete slashing");

        let slashing = ProposerSlashing {
            proposer_index: as_u64(slashing, "proposer_index")
                .expect("Incomplete slashing (proposer_index)"),
            proposal_data_1: ProposalSignedData {
                slot: Slot::from(
                    as_u64(slashing, "proposal_1_slot")
                        .expect("Incomplete slashing (proposal_1_slot)."),
                ),
                shard: as_u64(slashing, "proposal_1_shard")
                    .expect("Incomplete slashing (proposal_1_shard)."),
                block_root: as_hash256(slashing, "proposal_1_root")
                    .expect("Incomplete slashing (proposal_1_root)."),
            },
            proposal_signature_1: Signature::empty_signature(), // Will be replaced with real signature at runtime.
            proposal_data_2: ProposalSignedData {
                slot: Slot::from(
                    as_u64(slashing, "proposal_2_slot")
                        .expect("Incomplete slashing (proposal_2_slot)."),
                ),
                shard: as_u64(slashing, "proposal_2_shard")
                    .expect("Incomplete slashing (proposal_2_shard)."),
                block_root: as_hash256(slashing, "proposal_2_root")
                    .expect("Incomplete slashing (proposal_2_root)."),
            },
            proposal_signature_2: Signature::empty_signature(), // Will be replaced with real signature at runtime.
        };

        slashings.push((slot, slashing));
    }

    Some(slashings)
}

fn parse_deposits(yaml: &Yaml) -> Option<Vec<DepositTuple>> {
    let mut deposits = vec![];

    for deposit in yaml["deposits"].as_vec()? {
        let keypair = Keypair::random();
        let proof_of_possession = create_proof_of_possession(&keypair);

        let slot = as_u64(deposit, "slot").expect("Incomplete deposit");
        let deposit = Deposit {
            branch: vec![],
            index: as_u64(deposit, "merkle_index").unwrap(),
            deposit_data: DepositData {
                amount: 32_000_000_000,
                timestamp: 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(),
                    proof_of_possession,
                },
            },
        };

        deposits.push((slot, deposit, keypair));
    }

    Some(deposits)
}

fn as_usize(yaml: &Yaml, key: &str) -> Option<usize> {
    yaml[key].as_i64().and_then(|n| Some(n as usize))
}

fn as_u64(yaml: &Yaml, key: &str) -> Option<u64> {
    yaml[key].as_i64().and_then(|n| Some(n as u64))
}

fn as_hash256(yaml: &Yaml, key: &str) -> Option<Hash256> {
    yaml[key]
        .as_str()
        .and_then(|s| Some(Hash256::from(s.as_bytes())))
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
