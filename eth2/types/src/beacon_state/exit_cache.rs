use super::{ChainSpec, Epoch, Validator};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Map from exit epoch to the number of validators known to be exiting/exited at that epoch.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitCache(HashMap<Epoch, u64>);

impl ExitCache {
    /// Add all validators with a non-trivial exit epoch to the cache.
    pub fn build_from_registry(&mut self, validators: &[Validator], spec: &ChainSpec) {
        validators
            .iter()
            .filter(|validator| validator.exit_epoch != spec.far_future_epoch)
            .for_each(|validator| self.record_validator_exit(validator.exit_epoch));
    }

    /// Record the exit of a single validator in the cache.
    ///
    /// Must only be called once per exiting validator.
    pub fn record_validator_exit(&mut self, exit_epoch: Epoch) {
        *self.0.entry(exit_epoch).or_insert(0) += 1;
    }

    /// Get the greatest epoch for which validator exits are known.
    pub fn max_epoch(&self) -> Option<Epoch> {
        // This could probably be made even faster by caching the maximum.
        self.0.keys().max().cloned()
    }

    /// Get the number of validators exiting/exited at a given epoch, or zero if not known.
    pub fn get_churn_at(&self, epoch: Epoch) -> u64 {
        self.0.get(&epoch).cloned().unwrap_or(0)
    }
}
