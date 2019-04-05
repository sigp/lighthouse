use super::yaml_helpers::{as_u64, as_usize, as_vec_u64};
use log::info;
use types::*;
use yaml_rust::Yaml;

type ValidatorIndex = u64;
type BalanceGwei = u64;

type BalanceCheckTuple = (ValidatorIndex, String, BalanceGwei);

/// Tests to be conducted upon a `BeaconState` object generated during the execution of a
/// `TestCase`.
#[derive(Debug)]
pub struct StateCheck {
    /// Checked against `beacon_state.slot`.
    pub slot: Slot,
    /// Checked against `beacon_state.validator_registry.len()`.
    pub num_validators: Option<usize>,
    /// The number of pending attestations from the previous epoch that should be in the state.
    pub num_previous_epoch_attestations: Option<usize>,
    /// The number of pending attestations from the current epoch that should be in the state.
    pub num_current_epoch_attestations: Option<usize>,
    /// A list of validator indices which have been penalized. Must be in ascending order.
    pub slashed_validators: Option<Vec<u64>>,
    /// A list of validator indices which have been fully exited. Must be in ascending order.
    pub exited_validators: Option<Vec<u64>>,
    /// A list of validator indices which have had an exit initiated. Must be in ascending order.
    pub exit_initiated_validators: Option<Vec<u64>>,
    /// A list of balances to check.
    pub balances: Option<Vec<BalanceCheckTuple>>,
}

impl StateCheck {
    /// Load from a YAML document.
    ///
    /// Expects the `state_check` section of the YAML document.
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            slot: Slot::from(as_u64(&yaml, "slot").expect("State must specify slot")),
            num_validators: as_usize(&yaml, "num_validators"),
            num_previous_epoch_attestations: as_usize(&yaml, "num_previous_epoch_attestations"),
            num_current_epoch_attestations: as_usize(&yaml, "num_current_epoch_attestations"),
            slashed_validators: as_vec_u64(&yaml, "slashed_validators"),
            exited_validators: as_vec_u64(&yaml, "exited_validators"),
            exit_initiated_validators: as_vec_u64(&yaml, "exit_initiated_validators"),
            balances: parse_balances(&yaml),
        }
    }

    /// Performs all checks against a `BeaconState`
    ///
    /// # Panics
    ///
    /// Panics with an error message if any test fails.
    #[allow(clippy::cyclomatic_complexity)]
    pub fn assert_valid(&self, state: &BeaconState, spec: &ChainSpec) {
        let state_epoch = state.slot.epoch(spec.slots_per_epoch);

        info!("Running state check for slot height {}.", self.slot);

        // Check the state slot.
        assert_eq!(
            self.slot,
            state.slot - spec.genesis_epoch.start_slot(spec.slots_per_epoch),
            "State slot is invalid."
        );

        // Check the validator count
        if let Some(num_validators) = self.num_validators {
            assert_eq!(
                state.validator_registry.len(),
                num_validators,
                "State validator count != expected."
            );
            info!("OK: num_validators = {}.", num_validators);
        }

        // Check the previous epoch attestations
        if let Some(n) = self.num_previous_epoch_attestations {
            assert_eq!(
                state.previous_epoch_attestations.len(),
                n,
                "previous epoch attestations count != expected."
            );
            info!("OK: num_previous_epoch_attestations = {}.", n);
        }

        // Check the current epoch attestations
        if let Some(n) = self.num_current_epoch_attestations {
            assert_eq!(
                state.current_epoch_attestations.len(),
                n,
                "current epoch attestations count != expected."
            );
            info!("OK: num_current_epoch_attestations = {}.", n);
        }

        // Check for slashed validators.
        if let Some(ref slashed_validators) = self.slashed_validators {
            let actually_slashed_validators: Vec<u64> = state
                .validator_registry
                .iter()
                .enumerate()
                .filter_map(|(i, validator)| {
                    if validator.slashed {
                        Some(i as u64)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                actually_slashed_validators, *slashed_validators,
                "Slashed validators != expected."
            );
            info!("OK: slashed_validators = {:?}.", slashed_validators);
        }

        // Check for exited validators.
        if let Some(ref exited_validators) = self.exited_validators {
            let actually_exited_validators: Vec<u64> = state
                .validator_registry
                .iter()
                .enumerate()
                .filter_map(|(i, validator)| {
                    if validator.is_exited_at(state_epoch) {
                        Some(i as u64)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                actually_exited_validators, *exited_validators,
                "Exited validators != expected."
            );
            info!("OK: exited_validators = {:?}.", exited_validators);
        }

        // Check for validators that have initiated exit.
        if let Some(ref exit_initiated_validators) = self.exit_initiated_validators {
            let actual: Vec<u64> = state
                .validator_registry
                .iter()
                .enumerate()
                .filter_map(|(i, validator)| {
                    if validator.initiated_exit {
                        Some(i as u64)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                actual, *exit_initiated_validators,
                "Exit initiated validators != expected."
            );
            info!(
                "OK: exit_initiated_validators = {:?}.",
                exit_initiated_validators
            );
        }

        // Check validator balances.
        if let Some(ref balances) = self.balances {
            for (index, comparison, expected) in balances {
                let actual = *state
                    .validator_balances
                    .get(*index as usize)
                    .expect("Balance check specifies unknown validator");

                let result = match comparison.as_ref() {
                    "eq" => actual == *expected,
                    _ => panic!("Unknown balance comparison (use `eq`)"),
                };
                assert!(
                    result,
                    format!(
                        "Validator balance for {}: {} !{} {}.",
                        index, actual, comparison, expected
                    )
                );
                info!("OK: validator balance for {:?}.", index);
            }
        }
    }
}

/// Parse the `transfers` section of the YAML document.
fn parse_balances(yaml: &Yaml) -> Option<Vec<BalanceCheckTuple>> {
    let mut tuples = vec![];

    for exit in yaml["balances"].as_vec()? {
        let from =
            as_u64(exit, "validator_index").expect("Incomplete balance check (validator_index)");
        let comparison = exit["comparison"]
            .clone()
            .into_string()
            .expect("Incomplete balance check (amount)");
        let balance = as_u64(exit, "balance").expect("Incomplete balance check (balance)");

        tuples.push((from, comparison, balance));
    }

    Some(tuples)
}
