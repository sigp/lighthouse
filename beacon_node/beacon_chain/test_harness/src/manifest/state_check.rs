use super::yaml_helpers::{as_u64, as_usize, as_vec_u64};
use log::info;
use types::*;
use yaml_rust::Yaml;

/// Tests to be conducted upon a `BeaconState` object generated during the execution of a
/// `Manifest`.
#[derive(Debug)]
pub struct StateCheck {
    /// Checked against `beacon_state.slot`.
    pub slot: Slot,
    /// Checked against `beacon_state.validator_registry.len()`.
    pub num_validators: Option<usize>,
    /// A list of validator indices which have been penalized. Must be in ascending order.
    pub slashed_validators: Option<Vec<u64>>,
    /// A list of validator indices which have been exited. Must be in ascending order.
    pub exited_validators: Option<Vec<u64>>,
}

impl StateCheck {
    /// Load from a YAML document.
    ///
    /// Expects the `state_check` section of the YAML document.
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            slot: Slot::from(as_u64(&yaml, "slot").expect("State must specify slot")),
            num_validators: as_usize(&yaml, "num_validators"),
            slashed_validators: as_vec_u64(&yaml, "slashed_validators"),
            exited_validators: as_vec_u64(&yaml, "exited_validators"),
        }
    }

    /// Performs all checks against a `BeaconState`
    ///
    /// # Panics
    ///
    /// Panics with an error message if any test fails.
    pub fn assert_valid(&self, state: &BeaconState, spec: &ChainSpec) {
        let state_epoch = state.slot.epoch(spec.epoch_length);

        info!("Running state check for slot height {}.", self.slot);

        assert_eq!(
            self.slot,
            state.slot - spec.genesis_epoch.start_slot(spec.epoch_length),
            "State slot is invalid."
        );

        if let Some(num_validators) = self.num_validators {
            assert_eq!(
                state.validator_registry.len(),
                num_validators,
                "State validator count != expected."
            );
            info!("OK: num_validators = {}.", num_validators);
        }

        if let Some(ref slashed_validators) = self.slashed_validators {
            let actually_slashed_validators: Vec<u64> = state
                .validator_registry
                .iter()
                .enumerate()
                .filter_map(|(i, validator)| {
                    if validator.is_penalized_at(state_epoch) {
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
    }
}
