use super::{BeaconStateError, ChainSpec, Epoch, Validator};
use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Map from exit epoch to the number of validators with that exit epoch.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitCache {
    initialized: bool,
    exit_epoch_counts: HashMap<Epoch, u64>,
}

impl ExitCache {
    /// Initialize a new cache for the given list of validators.
    pub fn new(validators: &[Validator], spec: &ChainSpec) -> Result<Self, BeaconStateError> {
        let mut exit_cache = ExitCache {
            initialized: true,
            ..ExitCache::default()
        };
        // Add all validators with a non-default exit epoch to the cache.
        validators
            .iter()
            .filter(|validator| validator.exit_epoch != spec.far_future_epoch)
            .try_for_each(|validator| exit_cache.record_validator_exit(validator.exit_epoch))?;
        Ok(exit_cache)
    }

    /// Check that the cache is initialized and return an error if it is not.
    pub fn check_initialized(&self) -> Result<(), BeaconStateError> {
        if self.initialized {
            Ok(())
        } else {
            Err(BeaconStateError::ExitCacheUninitialized)
        }
    }

    /// Record the exit epoch of a validator. Must be called only once per exiting validator.
    pub fn record_validator_exit(&mut self, exit_epoch: Epoch) -> Result<(), BeaconStateError> {
        self.check_initialized()?;
        self.exit_epoch_counts
            .entry(exit_epoch)
            .or_insert(0)
            .safe_add_assign(1)?;
        Ok(())
    }

    /// Get the largest exit epoch with a non-zero exit epoch count.
    pub fn max_epoch(&self) -> Result<Option<Epoch>, BeaconStateError> {
        self.check_initialized()?;
        Ok(self.exit_epoch_counts.keys().max().cloned())
    }

    /// Get number of validators with the given exit epoch. (Return 0 for the default exit epoch.)
    pub fn get_churn_at(&self, exit_epoch: Epoch) -> Result<u64, BeaconStateError> {
        self.check_initialized()?;
        Ok(self
            .exit_epoch_counts
            .get(&exit_epoch)
            .cloned()
            .unwrap_or(0))
    }
}

#[cfg(feature = "arbitrary-fuzz")]
impl arbitrary::Arbitrary<'_> for ExitCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
