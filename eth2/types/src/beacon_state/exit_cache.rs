use super::{BeaconStateError, ChainSpec, Epoch, Validator};
use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Map from exit epoch to the number of validators known to be exiting/exited at that epoch.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitCache {
    initialized: bool,
    exits_per_epoch: HashMap<Epoch, u64>,
}

impl ExitCache {
    /// Ensure the cache is built, and do nothing if it's already initialized.
    pub fn build(
        &mut self,
        validators: &[Validator],
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        if self.initialized {
            Ok(())
        } else {
            self.force_build(validators, spec)
        }
    }

    /// Add all validators with a non-trivial exit epoch to the cache.
    pub fn force_build(
        &mut self,
        validators: &[Validator],
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        self.initialized = true;
        validators
            .iter()
            .filter(|validator| validator.exit_epoch != spec.far_future_epoch)
            .try_for_each(|validator| self.record_validator_exit(validator.exit_epoch))
    }

    /// Check that the cache is initialized and return an error if it isn't.
    pub fn check_initialized(&self) -> Result<(), BeaconStateError> {
        if self.initialized {
            Ok(())
        } else {
            Err(BeaconStateError::ExitCacheUninitialized)
        }
    }

    /// Record the exit of a single validator in the cache.
    ///
    /// Must only be called once per exiting validator.
    pub fn record_validator_exit(&mut self, exit_epoch: Epoch) -> Result<(), BeaconStateError> {
        self.check_initialized()?;
        self.exits_per_epoch
            .entry(exit_epoch)
            .or_insert(0)
            .increment()?;
        Ok(())
    }

    /// Get the greatest epoch for which validator exits are known.
    pub fn max_epoch(&self) -> Result<Option<Epoch>, BeaconStateError> {
        self.check_initialized()?;
        Ok(self.exits_per_epoch.keys().max().cloned())
    }

    /// Get the number of validators exiting/exited at a given epoch, or zero if not known.
    pub fn get_churn_at(&self, epoch: Epoch) -> Result<u64, BeaconStateError> {
        self.check_initialized()?;
        Ok(self.exits_per_epoch.get(&epoch).cloned().unwrap_or(0))
    }
}

#[cfg(feature = "arbitrary-fuzz")]
impl arbitrary::Arbitrary for ExitCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
