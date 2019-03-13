//! Defines execution and testing specs for a `BeaconChainHarness` instance. Supports loading from
//! a YAML file.

use crate::beacon_chain_harness::BeaconChainHarness;
use beacon_chain::CheckPoint;
use bls::get_withdrawal_credentials;
use log::{info, warn};
use ssz::SignedRoot;
use std::path::Path;
use types::*;

use types::test_utils::{TestingAttesterSlashingBuilder, TestingProposerSlashingBuilder};
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
/// 1. Instantiate the `TestCase` from YAML: `let test_case = TestCase::from_yaml(&my_yaml);`
/// 2. Execute the test_case: `let result = test_case.execute();`
/// 3. Test the results against the test_case: `test_case.assert_result_valid(result);`
#[derive(Debug)]
pub struct TestCase {
    /// Defines the execution.
    pub config: Config,
    /// Defines tests to run against the execution result.
    pub results: Results,
}

/// The result of executing a `TestCase`.
///
pub struct ExecutionResult {
    /// The canonical beacon chain generated from the execution.
    pub chain: Vec<CheckPoint>,
    /// The spec used for execution.
    pub spec: ChainSpec,
}

impl TestCase {
    /// Load the test case from a YAML document.
    pub fn from_yaml(test_case: &Yaml) -> Self {
        Self {
            results: Results::from_yaml(&test_case["results"]),
            config: Config::from_yaml(&test_case["config"]),
        }
    }

    /// Return a `ChainSpec::foundation()`.
    ///
    /// If specified in `config`, returns it with a modified `slots_per_epoch`.
    fn spec(&self) -> ChainSpec {
        let mut spec = ChainSpec::foundation();

        if let Some(n) = self.config.slots_per_epoch {
            spec.slots_per_epoch = n;
        }

        spec
    }

    /// Executes the test case, returning an `ExecutionResult`.
    #[allow(clippy::cyclomatic_complexity)]
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

        // Start at 1 because genesis counts as a slot.
        for slot_height in 1..slots {
            // Used to ensure that deposits in the same slot have incremental deposit indices.
            let mut deposit_index_offset = 0;

            // Feed deposits to the BeaconChain.
            if let Some(ref deposits) = self.config.deposits {
                for (slot, amount) in deposits {
                    if *slot == slot_height {
                        info!("Including deposit at slot height {}.", slot_height);
                        let (deposit, keypair) =
                            build_deposit(&harness, *amount, deposit_index_offset);
                        harness.add_deposit(deposit, Some(keypair.clone()));
                        deposit_index_offset += 1;
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

            // Feed exits to the BeaconChain.
            if let Some(ref exits) = self.config.exits {
                for (slot, validator_index) in exits {
                    if *slot == slot_height {
                        info!(
                            "Including exit at slot height {} for validator {}.",
                            slot_height, validator_index
                        );
                        let exit = build_exit(&harness, *validator_index);
                        harness.add_exit(exit);
                    }
                }
            }

            // Feed transfers to the BeaconChain.
            if let Some(ref transfers) = self.config.transfers {
                for (slot, from, to, amount) in transfers {
                    if *slot == slot_height {
                        info!(
                            "Including transfer at slot height {} from validator {}.",
                            slot_height, from
                        );
                        let transfer = build_transfer(&harness, *from, *to, *amount);
                        harness.add_transfer(transfer);
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
                        state.slot - spec.genesis_epoch.start_slot(spec.slots_per_epoch);

                    if state_check.slot == adjusted_state_slot {
                        state_check.assert_valid(state, spec);
                    }
                }
            }
        }
    }
}

/// Builds a `Deposit` this is valid for the given `BeaconChainHarness` at its next slot.
fn build_transfer(harness: &BeaconChainHarness, from: u64, to: u64, amount: u64) -> Transfer {
    let slot = harness.beacon_chain.state.read().slot + 1;

    let mut transfer = Transfer {
        from,
        to,
        amount,
        fee: 0,
        slot,
        pubkey: harness.validators[from as usize].keypair.pk.clone(),
        signature: Signature::empty_signature(),
    };

    let message = transfer.signed_root();
    let epoch = slot.epoch(harness.spec.slots_per_epoch);

    transfer.signature = harness
        .validator_sign(from as usize, &message[..], epoch, Domain::Transfer)
        .expect("Unable to sign Transfer");

    transfer
}

/// Builds a `Deposit` this is valid for the given `BeaconChainHarness`.
///
/// `index_offset` is used to ensure that `deposit.index == state.index` when adding multiple
/// deposits.
fn build_deposit(
    harness: &BeaconChainHarness,
    amount: u64,
    index_offset: u64,
) -> (Deposit, Keypair) {
    let keypair = Keypair::random();
    let withdrawal_credentials = Hash256::from_slice(
        &get_withdrawal_credentials(&keypair.pk, harness.spec.bls_withdrawal_prefix_byte)[..],
    );
    let proof_of_possession = DepositInput::create_proof_of_possession(
        &keypair,
        &withdrawal_credentials,
        harness.spec.get_domain(
            harness
                .beacon_chain
                .state
                .read()
                .current_epoch(&harness.spec),
            Domain::Deposit,
            &harness.beacon_chain.state.read().fork,
        ),
    );
    let index = harness.beacon_chain.state.read().deposit_index + index_offset;

    let deposit = Deposit {
        // Note: `branch` and `index` will need to be updated once the spec defines their
        // validity.
        branch: vec![],
        index,
        deposit_data: DepositData {
            amount,
            timestamp: 1,
            deposit_input: DepositInput {
                pubkey: keypair.pk.clone(),
                withdrawal_credentials,
                proof_of_possession,
            },
        },
    };

    (deposit, keypair)
}

/// Builds a `VoluntaryExit` this is valid for the given `BeaconChainHarness`.
fn build_exit(harness: &BeaconChainHarness, validator_index: u64) -> VoluntaryExit {
    let epoch = harness
        .beacon_chain
        .state
        .read()
        .current_epoch(&harness.spec);

    let mut exit = VoluntaryExit {
        epoch,
        validator_index,
        signature: Signature::empty_signature(),
    };

    let message = exit.signed_root();

    exit.signature = harness
        .validator_sign(validator_index as usize, &message[..], epoch, Domain::Exit)
        .expect("Unable to sign VoluntaryExit");

    exit
}

/// Builds an `AttesterSlashing` for some `validator_indices`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_double_vote_attester_slashing(
    harness: &BeaconChainHarness,
    validator_indices: &[u64],
) -> AttesterSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        harness
            .validator_sign(validator_index as usize, message, epoch, domain)
            .expect("Unable to sign AttesterSlashing")
    };

    TestingAttesterSlashingBuilder::double_vote(validator_indices, signer)
}

/// Builds an `ProposerSlashing` for some `validator_index`.
///
/// Signs the message using a `BeaconChainHarness`.
fn build_proposer_slashing(harness: &BeaconChainHarness, validator_index: u64) -> ProposerSlashing {
    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        harness
            .validator_sign(validator_index as usize, message, epoch, domain)
            .expect("Unable to sign AttesterSlashing")
    };

    TestingProposerSlashingBuilder::double_vote(validator_index, signer, &harness.spec)
}
