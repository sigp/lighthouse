#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use rpds::HashTrieSetSync as HashTrieSet;

use crate::{core::Slot, state::BeaconStateError, validator::Validator};

/// Persistent (cheap to clone) cache of all slashed validator indices.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SlashingsCache {
    latest_block_slot: Option<Slot>,
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    slashed_validators: HashTrieSet<usize>,
}

impl SlashingsCache {
    /// Initialize a new cache for the given list of validators.
    pub fn new<'a, V, I>(latest_block_slot: Slot, validators: V) -> Self
    where
        V: IntoIterator<Item = &'a Validator, IntoIter = I>,
        I: ExactSizeIterator + Iterator<Item = &'a Validator>,
    {
        let slashed_validators = validators
            .into_iter()
            .enumerate()
            .filter_map(|(i, validator)| validator.slashed.then_some(i))
            .collect();
        Self {
            latest_block_slot: Some(latest_block_slot),
            slashed_validators,
        }
    }

    pub fn is_initialized(&self, slot: Slot) -> bool {
        self.latest_block_slot == Some(slot)
    }

    pub fn check_initialized(&self, latest_block_slot: Slot) -> Result<(), BeaconStateError> {
        if self.is_initialized(latest_block_slot) {
            Ok(())
        } else {
            Err(BeaconStateError::SlashingsCacheUninitialized {
                initialized_slot: self.latest_block_slot,
                latest_block_slot,
            })
        }
    }

    pub fn record_validator_slashing(
        &mut self,
        block_slot: Slot,
        validator_index: usize,
    ) -> Result<(), BeaconStateError> {
        self.check_initialized(block_slot)?;
        self.slashed_validators.insert_mut(validator_index);
        Ok(())
    }

    pub fn is_slashed(&self, validator_index: usize) -> bool {
        self.slashed_validators.contains(&validator_index)
    }

    pub fn update_latest_block_slot(&mut self, latest_block_slot: Slot) {
        self.latest_block_slot = Some(latest_block_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Hash256};
    use bls::PublicKeyBytes;

    /// Build a minimal validator with the given `slashed` flag. The other fields are irrelevant to
    /// the slashings cache.
    fn validator(slashed: bool) -> Validator {
        Validator {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::ZERO,
            effective_balance: 0,
            slashed,
            activation_eligibility_epoch: Epoch::new(0),
            activation_epoch: Epoch::new(0),
            exit_epoch: Epoch::new(0),
            withdrawable_epoch: Epoch::new(0),
        }
    }

    /// Validators 1 and 3 are slashed, the rest are not.
    fn validators() -> Vec<Validator> {
        vec![
            validator(false),
            validator(true),
            validator(false),
            validator(true),
            validator(false),
        ]
    }

    #[test]
    fn new_captures_slashed_indices() {
        let validators = validators();
        let cache = SlashingsCache::new(Slot::new(7), validators.iter());

        // The cache is initialized at the block slot it was built for.
        assert!(cache.is_initialized(Slot::new(7)));
        assert!(!cache.is_initialized(Slot::new(8)));

        // Each index reports the same `slashed` status as the source validator.
        for (index, validator) in validators.iter().enumerate() {
            assert_eq!(
                cache.is_slashed(index),
                validator.slashed,
                "validator {index} slashed status mismatch"
            );
        }

        // An out-of-bounds index is not slashed.
        assert!(!cache.is_slashed(validators.len()));
    }

    #[test]
    fn default_is_uninitialized() {
        let cache = SlashingsCache::default();

        // A default cache is not initialized at any slot.
        assert!(!cache.is_initialized(Slot::new(0)));
        assert_eq!(
            cache.check_initialized(Slot::new(0)),
            Err(BeaconStateError::SlashingsCacheUninitialized {
                initialized_slot: None,
                latest_block_slot: Slot::new(0),
            })
        );

        // It reports nothing as slashed. This is exactly why callers must check initialization
        // before trusting `is_slashed`.
        assert!(!cache.is_slashed(0));
    }

    #[test]
    fn check_initialized_matches_block_slot() {
        let cache = SlashingsCache::new(Slot::new(3), validators().iter());

        assert_eq!(cache.check_initialized(Slot::new(3)), Ok(()));
        assert_eq!(
            cache.check_initialized(Slot::new(4)),
            Err(BeaconStateError::SlashingsCacheUninitialized {
                initialized_slot: Some(Slot::new(3)),
                latest_block_slot: Slot::new(4),
            })
        );
    }

    #[test]
    fn record_validator_slashing_requires_matching_slot() {
        let mut cache = SlashingsCache::new(Slot::new(3), validators().iter());

        // Index 0 starts unslashed.
        assert!(!cache.is_slashed(0));

        // Recording at the initialized slot succeeds and marks the validator slashed.
        cache.record_validator_slashing(Slot::new(3), 0).unwrap();
        assert!(cache.is_slashed(0));

        // Recording at a slot the cache is not initialized for errors and leaves the set unchanged.
        assert_eq!(
            cache.record_validator_slashing(Slot::new(4), 2),
            Err(BeaconStateError::SlashingsCacheUninitialized {
                initialized_slot: Some(Slot::new(3)),
                latest_block_slot: Slot::new(4),
            })
        );
        assert!(!cache.is_slashed(2));
    }

    #[test]
    fn update_latest_block_slot_preserves_slashed_set() {
        let mut cache = SlashingsCache::new(Slot::new(3), validators().iter());

        cache.update_latest_block_slot(Slot::new(4));

        // The initialized slot moves forward without clearing the recorded slashings.
        assert!(!cache.is_initialized(Slot::new(3)));
        assert!(cache.is_initialized(Slot::new(4)));
        assert!(cache.is_slashed(1));
        assert!(cache.is_slashed(3));
        assert!(!cache.is_slashed(0));
    }
}
