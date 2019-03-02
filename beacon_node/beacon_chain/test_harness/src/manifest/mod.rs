use self::config::Config;
use self::results::Results;
use crate::beacon_chain_harness::BeaconChainHarness;
use beacon_chain::CheckPoint;
use log::{info, warn};
use types::*;
use types::{
    attester_slashing::AttesterSlashingBuilder, proposer_slashing::ProposerSlashingBuilder,
};
use yaml_rust::Yaml;

mod config;
mod results;
mod yaml_helpers;

pub struct Manifest {
    pub results: Results,
    pub config: Config,
}

pub struct ExecutionResult {
    pub chain: Vec<CheckPoint>,
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
                for (slot, validator_index) in slashings {
                    if *slot == slot_height {
                        info!(
                            "Including proposer slashing at slot height {} for validator #{}.",
                            slot_height, validator_index
                        );
                        let slashing = build_proposer_slashing(&harness, *validator_index);
                        harness.add_proposer_slashing(slashing);
                    }
                }
            }

            // Feed attester slashings to the BeaconChain.
            if let Some(ref slashings) = self.config.attester_slashings {
                for (slot, validator_indices) in slashings {
                    if *slot == slot_height {
                        info!(
                            "Including attester slashing at slot height {} for validators {:?}.",
                            slot_height, validator_indices
                        );
                        let slashing =
                            build_double_vote_attester_slashing(&harness, &validator_indices[..]);
                        harness.add_attester_slashing(slashing);
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

fn build_double_vote_attester_slashing(
    harness: &BeaconChainHarness,
    validator_indices: &[u64],
) -> AttesterSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: u64| {
        harness
            .validator_sign(validator_index as usize, message, epoch, domain)
            .expect("Unable to sign AttesterSlashing")
    };

    AttesterSlashingBuilder::double_vote(validator_indices, signer, &harness.spec)
}

fn build_proposer_slashing(harness: &BeaconChainHarness, validator_index: u64) -> ProposerSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: u64| {
        harness
            .validator_sign(validator_index as usize, message, epoch, domain)
            .expect("Unable to sign AttesterSlashing")
    };

    ProposerSlashingBuilder::double_vote(validator_index, signer, &harness.spec)
}
