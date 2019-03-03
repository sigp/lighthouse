//! Defines execution and testing specs for a `BeaconChainHarness` instance. Supports loading from
//! a YAML file.

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
mod state_check;
mod yaml_helpers;

pub use config::Config;
pub use results::Results;
pub use state_check::StateCheck;

/// Defines the execution and testing of a `BeaconChainHarness` instantiation.
///
/// Typical workflow is:
///
/// 1. Instantiate the `Manifest` from YAML: `let manifest = Manifest::from_yaml(&my_yaml);`
/// 2. Execute the manifest: `let result = manifest.execute();`
/// 3. Test the results against the manifest: `manifest.assert_result_valid(result);`
#[derive(Debug)]
pub struct Manifest {
    /// Defines the execution.
    pub config: Config,
    /// Defines tests to run against the execution result.
    pub results: Results,
}

/// The result of executing a `Manifest`.
///
pub struct ExecutionResult {
    /// The canonical beacon chain generated from the execution.
    pub chain: Vec<CheckPoint>,
    /// The spec used for execution.
    pub spec: ChainSpec,
}

impl Manifest {
    /// Load the manifest from a YAML document.
    pub fn from_yaml(test_case: &Yaml) -> Self {
        Self {
            results: Results::from_yaml(&test_case["results"]),
            config: Config::from_yaml(&test_case["config"]),
        }
    }

    /// Return a `ChainSpec::foundation()`.
    ///
    /// If specified in `config`, returns it with a modified `epoch_length`.
    fn spec(&self) -> ChainSpec {
        let mut spec = ChainSpec::foundation();

        if let Some(n) = self.config.epoch_length {
            spec.epoch_length = n;
        }

        spec
    }

    /// Executes the manifest, returning an `ExecutionResult`.
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

        // -1 slots because genesis counts as a slot.
        for slot_height in 0..slots - 1 {
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

        info!("Building chain dump for analysis...");

        ExecutionResult {
            chain: harness.chain_dump().expect("Chain dump failed."),
            spec: (*harness.spec).clone(),
        }
    }

    /// Checks that the `ExecutionResult` is consistent with the specifications in `self.results`.
    ///
    /// # Panics
    ///
    /// Panics with a message if any result does not match exepectations.
    pub fn assert_result_valid(&self, execution_result: ExecutionResult) {
        info!("Verifying test results...");
        let spec = &execution_result.spec;

        if let Some(num_skipped_slots) = self.results.num_skipped_slots {
            assert_eq!(
                execution_result.chain.len(),
                self.config.num_slots as usize - num_skipped_slots,
                "actual skipped slots != expected."
            );
            info!(
                "OK: Chain length is {} ({} skipped slots).",
                execution_result.chain.len(),
                num_skipped_slots
            );
        }

        if let Some(ref state_checks) = self.results.state_checks {
            for checkpoint in &execution_result.chain {
                let state = &checkpoint.beacon_state;

                for state_check in state_checks {
                    let adjusted_state_slot =
                        state.slot - spec.genesis_epoch.start_slot(spec.epoch_length);

                    if state_check.slot == adjusted_state_slot {
                        state_check.assert_valid(state, spec);
                    }
                }
            }
        }
    }
}

/// Builds an `AttesterSlashing` for some `validator_indices`.
///
/// Signs the message using a `BeaconChainHarness`.
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

/// Builds an `ProposerSlashing` for some `validator_index`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_proposer_slashing(harness: &BeaconChainHarness, validator_index: u64) -> ProposerSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: u64| {
        harness
            .validator_sign(validator_index as usize, message, epoch, domain)
            .expect("Unable to sign AttesterSlashing")
    };

    ProposerSlashingBuilder::double_vote(validator_index, signer, &harness.spec)
}
