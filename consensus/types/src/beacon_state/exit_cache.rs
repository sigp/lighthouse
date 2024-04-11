use super::{BeaconStateError, ChainSpec, Epoch, Validator};
use safe_arith::SafeArith;
use std::cmp::Ordering;

/// Map from exit epoch to the number of validators with that exit epoch.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ExitCache {
    /// True if the cache has been initialized.
    initialized: bool,
    /// Maximum `exit_epoch` of any validator.
    max_exit_epoch: Epoch,
    /// Number of validators known to be exiting at `max_exit_epoch`.
    max_exit_epoch_churn: u64,
}

impl ExitCache {
    /// Initialize a new cache for the given list of validators.
    pub fn new<'a, V, I>(validators: V, spec: &ChainSpec) -> Result<Self, BeaconStateError>
    where
        V: IntoIterator<Item = &'a Validator, IntoIter = I>,
        I: ExactSizeIterator + Iterator<Item = &'a Validator>,
    {
        let mut exit_cache = ExitCache {
            initialized: true,
            max_exit_epoch: Epoch::new(0),
            max_exit_epoch_churn: 0,
        };
        // Add all validators with a non-default exit epoch to the cache.
        validators
            .into_iter()
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
        match exit_epoch.cmp(&self.max_exit_epoch) {
            // Update churn for the current maximum epoch.
            Ordering::Equal => {
                self.max_exit_epoch_churn.safe_add_assign(1)?;
            }
            // Increase the max exit epoch, reset the churn to 1.
            Ordering::Greater => {
                self.max_exit_epoch = exit_epoch;
                self.max_exit_epoch_churn = 1;
            }
            // Older exit epochs are not relevant.
            Ordering::Less => (),
        }
        Ok(())
    }

    /// Get the largest exit epoch with a non-zero exit epoch count.
    pub fn max_epoch(&self) -> Result<Option<Epoch>, BeaconStateError> {
        self.check_initialized()?;
        Ok((self.max_exit_epoch_churn > 0).then_some(self.max_exit_epoch))
    }

    /// Get number of validators with the given exit epoch. (Return 0 for the default exit epoch.)
    pub fn get_churn_at(&self, exit_epoch: Epoch) -> Result<u64, BeaconStateError> {
        self.check_initialized()?;
        match exit_epoch.cmp(&self.max_exit_epoch) {
            // Epochs are equal, we know the churn exactly.
            Ordering::Equal => Ok(self.max_exit_epoch_churn),
            // If exiting at an epoch later than the cached epoch then the churn is 0. This is a
            // common case which happens when there are no exits for an epoch.
            Ordering::Greater => Ok(0),
            // Consensus code should never require the churn at an epoch prior to the cached epoch.
            // That's a bug.
            Ordering::Less => Err(BeaconStateError::ExitCacheInvalidEpoch {
                max_exit_epoch: self.max_exit_epoch,
                request_epoch: exit_epoch,
            }),
        }
    }
}

impl arbitrary::Arbitrary<'_> for ExitCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
