use crate::*;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    EpochTooLow { base: Epoch, other: Epoch },
    EpochTooHigh { base: Epoch, other: Epoch },
}

/// Defines the epochs relative to some epoch. Most useful when referring to the committees prior
/// to and following some epoch.
///
/// Spec v0.8.1
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RelativeEpoch {
    /// The prior epoch.
    Previous,
    /// The current epoch.
    Current,
    /// The next epoch.
    Next,
}

impl RelativeEpoch {
    /// Returns the `epoch` that `self` refers to, with respect to the `base` epoch.
    ///
    /// Spec v0.8.1
    pub fn into_epoch(self, base: Epoch) -> Epoch {
        match self {
            // Due to saturating nature of epoch, check for current first.
            RelativeEpoch::Current => base,
            RelativeEpoch::Previous => base - 1,
            RelativeEpoch::Next => base + 1,
        }
    }

    /// Converts the `other` epoch into a `RelativeEpoch`, with respect to `base`
    ///
    /// ## Errors
    /// Returns an error when:
    /// - `EpochTooLow` when `other` is more than 1 prior to `base`.
    /// - `EpochTooHigh` when `other` is more than 1 after `base`.
    ///
    /// Spec v0.8.1
    pub fn from_epoch(base: Epoch, other: Epoch) -> Result<Self, Error> {
        // Due to saturating nature of epoch, check for current first.
        if other == base {
            Ok(RelativeEpoch::Current)
        } else if other == base - 1 {
            Ok(RelativeEpoch::Previous)
        } else if other == base + 1 {
            Ok(RelativeEpoch::Next)
        } else if other < base {
            Err(Error::EpochTooLow { base, other })
        } else {
            Err(Error::EpochTooHigh { base, other })
        }
    }

    /// Convenience function for `Self::from_epoch` where both slots are converted into epochs.
    pub fn from_slot(base: Slot, other: Slot, slots_per_epoch: u64) -> Result<Self, Error> {
        Self::from_epoch(base.epoch(slots_per_epoch), other.epoch(slots_per_epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_epoch() {
        let base = Epoch::new(10);

        assert_eq!(RelativeEpoch::Current.into_epoch(base), base);
        assert_eq!(RelativeEpoch::Previous.into_epoch(base), base - 1);
        assert_eq!(RelativeEpoch::Next.into_epoch(base), base + 1);
    }

    #[test]
    fn from_epoch() {
        let base = Epoch::new(10);

        assert_eq!(
            RelativeEpoch::from_epoch(base, base - 1),
            Ok(RelativeEpoch::Previous)
        );
        assert_eq!(
            RelativeEpoch::from_epoch(base, base),
            Ok(RelativeEpoch::Current)
        );
        assert_eq!(
            RelativeEpoch::from_epoch(base, base + 1),
            Ok(RelativeEpoch::Next)
        );
    }

    #[test]
    fn from_slot() {
        let slots_per_epoch: u64 = 64;
        let base = Slot::new(10 * slots_per_epoch);

        assert_eq!(
            RelativeEpoch::from_slot(base, base - 1, slots_per_epoch),
            Ok(RelativeEpoch::Previous)
        );
        assert_eq!(
            RelativeEpoch::from_slot(base, base, slots_per_epoch),
            Ok(RelativeEpoch::Current)
        );
        assert_eq!(
            RelativeEpoch::from_slot(base, base + slots_per_epoch, slots_per_epoch),
            Ok(RelativeEpoch::Next)
        );
    }
}
