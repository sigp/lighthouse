use super::{BeaconStateError, ChainSpec, Epoch, Validator};
use rpds::HashTrieMapSync as HashTrieMap;
use safe_arith::SafeArith;

/// Map from exit epoch to the number of validators with that exit epoch.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ExitCache {
    initialized: bool,
    exit_epoch_counts: HashTrieMap<Epoch, u64>,
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
            ..ExitCache::default()
        };
        // Add all validators with a non-default exit epoch to the cache.
        validators
            .into_iter()
            .filter(|validator| validator.exit_epoch() != spec.far_future_epoch)
            .try_for_each(|validator| exit_cache.record_validator_exit(validator.exit_epoch()))?;
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

        if let Some(count) = self.exit_epoch_counts.get_mut(&exit_epoch) {
            count.safe_add_assign(1)?;
        } else {
            self.exit_epoch_counts.insert_mut(exit_epoch, 1);
        }
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

impl arbitrary::Arbitrary<'_> for ExitCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
