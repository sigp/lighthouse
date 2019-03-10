use super::BeaconStateError;
use crate::validator_registry::get_active_validator_indices;
use crate::*;
use rayon::prelude::*;
use ssz::TreeHash;

/// Builds a `BeaconState` for use in production.
///
/// This struct should not be modified for use in testing scenarios. Use `TestingBeaconStateBuilder` for that purpose.
///
/// This struct should remain safe and sensible for production usage.
pub struct BeaconStateBuilder {
    pub state: BeaconState,
}

impl BeaconStateBuilder {
    /// Create a new builder with the given number of validators.
    ///
    /// Spec v0.4.0
    pub fn new(genesis_time: u64, latest_eth1_data: Eth1Data, spec: &ChainSpec) -> Self {
        Self {
            state: BeaconState::genesis(genesis_time, latest_eth1_data, spec),
        }
    }

    /// Process deposit objects.
    ///
    /// Spec v0.4.0
    pub fn process_initial_deposits(
        &mut self,
        initial_validator_deposits: &[Deposit],
        spec: &ChainSpec,
    ) {
        let deposit_data = initial_validator_deposits
            .par_iter()
            .map(|deposit| &deposit.deposit_data)
            .collect();

        self.state.process_deposits(deposit_data, spec);

        self.activate_genesis_validators(spec);

        self.state.deposit_index = initial_validator_deposits.len() as u64;
    }

    fn activate_genesis_validators(&mut self, spec: &ChainSpec) {
        for validator_index in 0..self.state.validator_registry.len() {
            if self.state.get_effective_balance(validator_index, spec) >= spec.max_deposit_amount {
                self.state.activate_validator(validator_index, true, spec);
            }
        }
    }

    /// Instantiate the validator registry from a YAML file.
    ///
    /// This skips a lot of signing and verification, useful for fast test setups.
    ///
    /// Spec v0.4.0
    pub fn import_existing_validators(
        &mut self,
        validators: Vec<Validator>,
        initial_balances: Vec<u64>,
        deposit_index: u64,
        spec: &ChainSpec,
    ) {
        self.state.validator_registry = validators;

        assert_eq!(
            self.state.validator_registry.len(),
            initial_balances.len(),
            "Not enough balances for validators"
        );

        self.state.validator_balances = initial_balances;

        self.activate_genesis_validators(spec);

        self.state.deposit_index = deposit_index;
    }

    /// Updates the final state variables and returns a fully built genesis state.
    ///
    /// Spec v0.4.0
    pub fn build(mut self, spec: &ChainSpec) -> Result<BeaconState, BeaconStateError> {
        let genesis_active_index_root =
            get_active_validator_indices(&self.state.validator_registry, spec.genesis_epoch)
                .hash_tree_root();

        self.state.latest_active_index_roots = vec![
            Hash256::from_slice(&genesis_active_index_root);
            spec.latest_active_index_roots_length
        ];

        self.state.current_shuffling_seed = self.state.generate_seed(spec.genesis_epoch, spec)?;

        Ok(self.state)
    }
}
