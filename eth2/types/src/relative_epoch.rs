use crate::*;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    EpochTooLow { base: Epoch, other: Epoch },
    EpochTooHigh { base: Epoch, other: Epoch },
    AmbiguiousNextEpoch,
}

/// Defines the epochs relative to some epoch. Most useful when referring to the committees prior
/// to and following some epoch.
///
/// Spec v0.5.0
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RelativeEpoch {
    /// The prior epoch.
    Previous,
    /// The current epoch.
    Current,
    /// The next epoch if there _is_ a validator registry update.
    ///
    /// If the validator registry is updated during an epoch transition, a new shuffling seed is
    /// generated, this changes the attestation and proposal roles.
    NextWithRegistryChange,
    /// The next epoch if there _is not_ a validator registry update.
    ///
    /// If the validator registry _is not_ updated during an epoch transition, the shuffling stays
    /// the same.
    NextWithoutRegistryChange,
}

impl RelativeEpoch {
    /// Returns the `epoch` that `self` refers to, with respect to the `base` epoch.
    ///
    /// Spec v0.5.0
    pub fn into_epoch(&self, base: Epoch) -> Epoch {
        match self {
            RelativeEpoch::Previous => base - 1,
            RelativeEpoch::Current => base,
            RelativeEpoch::NextWithoutRegistryChange => base + 1,
            RelativeEpoch::NextWithRegistryChange => base + 1,
        }
    }

    /// Converts the `other` epoch into a `RelativeEpoch`, with respect to `base`
    ///
    /// ## Errors
    /// Returns an error when:
    /// - `EpochTooLow` when `other` is more than 1 prior to `base`.
    /// - `EpochTooHigh` when `other` is more than 1 after `base`.
    /// - `AmbiguiousNextEpoch` whenever `other` is one after `base`, because it's unknowable if
    ///   there will be a registry change.
    ///
    /// Spec v0.5.0
    pub fn from_epoch(base: Epoch, other: Epoch) -> Result<Self, Error> {
        if other == base - 1 {
            Ok(RelativeEpoch::Previous)
        } else if other == base {
            Ok(RelativeEpoch::Current)
        } else if other == base + 1 {
            Err(Error::AmbiguiousNextEpoch)
        } else if other < base {
            Err(Error::EpochTooLow { base, other })
        } else {
            Err(Error::EpochTooHigh { base, other })
        }
    }

    /// Convenience function for `Self::from_epoch` where both slots are converted into epochs.
    pub fn from_slot(base: Slot, other: Slot, spec: &ChainSpec) -> Result<Self, Error> {
        Self::from_epoch(
            base.epoch(spec.slots_per_epoch),
            other.epoch(spec.slots_per_epoch),
        )
    }
}
