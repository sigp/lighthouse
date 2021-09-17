//! The `Slot` and `Epoch` types are defined as new types over u64 to enforce type-safety between
//! the two types.
//!
//! `Slot` and `Epoch` have implementations which permit conversion, comparison and math operations
//! between each and `u64`, however specifically not between each other.
//!
//! All math operations on `Slot` and `Epoch` are saturating, they never wrap.
//!
//! It would be easy to define `PartialOrd` and other traits generically across all types which
//! implement `Into<u64>`, however this would allow operations between `Slots` and `Epochs` which
//! may lead to programming errors which are not detected by the compiler.

use crate::test_utils::TestRandom;
use crate::{ChainSpec, SignedRoot};

use rand::RngCore;
use safe_arith::{ArithError, SafeArith};
use serde_derive::{Deserialize, Serialize};
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use std::fmt;
use std::hash::Hash;
use std::iter::Iterator;

#[cfg(feature = "legacy-arith")]
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Slot(#[serde(with = "eth2_serde_utils::quoted_u64")] u64);

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Epoch(#[serde(with = "eth2_serde_utils::quoted_u64")] u64);

impl_common!(Slot);
impl_common!(Epoch);

impl Slot {
    pub const fn new(slot: u64) -> Slot {
        Slot(slot)
    }

    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch::new(self.0)
            .safe_div(slots_per_epoch)
            .expect("slots_per_epoch is not 0")
    }

    pub fn max_value() -> Slot {
        Slot(u64::max_value())
    }
}

impl Epoch {
    pub const fn new(slot: u64) -> Epoch {
        Epoch(slot)
    }

    pub fn max_value() -> Epoch {
        Epoch(u64::max_value())
    }

    /// The first slot in the epoch.
    pub fn start_slot(self, slots_per_epoch: u64) -> Slot {
        Slot::from(self.0.saturating_mul(slots_per_epoch))
    }

    /// The last slot in the epoch.
    pub fn end_slot(self, slots_per_epoch: u64) -> Slot {
        Slot::from(
            self.0
                .saturating_mul(slots_per_epoch)
                .saturating_add(slots_per_epoch.saturating_sub(1)),
        )
    }

    /// Position of some slot inside an epoch, if any.
    ///
    /// E.g., the first `slot` in `epoch` is at position `0`.
    pub fn position(self, slot: Slot, slots_per_epoch: u64) -> Option<usize> {
        let start = self.start_slot(slots_per_epoch);
        let end = self.end_slot(slots_per_epoch);

        if slot >= start && slot <= end {
            slot.as_usize().checked_sub(start.as_usize())
        } else {
            None
        }
    }

    /// Compute the sync committee period for an epoch.
    pub fn sync_committee_period(&self, spec: &ChainSpec) -> Result<u64, ArithError> {
        Ok(self
            .safe_div(spec.epochs_per_sync_committee_period)?
            .as_u64())
    }

    pub fn slot_iter(&self, slots_per_epoch: u64) -> SlotIter {
        SlotIter {
            current_iteration: 0,
            epoch: self,
            slots_per_epoch,
        }
    }
}

pub struct SlotIter<'a> {
    current_iteration: u64,
    epoch: &'a Epoch,
    slots_per_epoch: u64,
}

impl<'a> Iterator for SlotIter<'a> {
    type Item = Slot;

    fn next(&mut self) -> Option<Slot> {
        if self.current_iteration >= self.slots_per_epoch {
            None
        } else {
            let start_slot = self.epoch.start_slot(self.slots_per_epoch);
            let previous = self.current_iteration;
            self.current_iteration = self.current_iteration.checked_add(1)?;
            start_slot.safe_add(previous).ok()
        }
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;

    all_tests!(Slot);
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    all_tests!(Epoch);

    #[test]
    fn epoch_start_end() {
        let slots_per_epoch = 8;

        let epoch = Epoch::new(0);

        assert_eq!(epoch.start_slot(slots_per_epoch), Slot::new(0));
        assert_eq!(epoch.end_slot(slots_per_epoch), Slot::new(7));
    }

    #[test]
    fn end_slot_boundary_test() {
        let slots_per_epoch = 32;

        // The last epoch which can be represented by u64.
        let epoch = Epoch::new(u64::max_value() / slots_per_epoch);

        // A slot number on the epoch should be equal to u64::max_value.
        assert_eq!(epoch.end_slot(slots_per_epoch), Slot::new(u64::max_value()));
    }

    #[test]
    fn position() {
        let slots_per_epoch = 8;

        let epoch = Epoch::new(0);
        assert_eq!(epoch.position(Slot::new(0), slots_per_epoch), Some(0));
        assert_eq!(epoch.position(Slot::new(1), slots_per_epoch), Some(1));
        assert_eq!(epoch.position(Slot::new(2), slots_per_epoch), Some(2));
        assert_eq!(epoch.position(Slot::new(3), slots_per_epoch), Some(3));
        assert_eq!(epoch.position(Slot::new(4), slots_per_epoch), Some(4));
        assert_eq!(epoch.position(Slot::new(5), slots_per_epoch), Some(5));
        assert_eq!(epoch.position(Slot::new(6), slots_per_epoch), Some(6));
        assert_eq!(epoch.position(Slot::new(7), slots_per_epoch), Some(7));
        assert_eq!(epoch.position(Slot::new(8), slots_per_epoch), None);

        let epoch = Epoch::new(1);
        assert_eq!(epoch.position(Slot::new(7), slots_per_epoch), None);
        assert_eq!(epoch.position(Slot::new(8), slots_per_epoch), Some(0));
    }

    #[test]
    fn slot_iter() {
        let slots_per_epoch = 8;

        let epoch = Epoch::new(0);

        let mut slots = vec![];
        for slot in epoch.slot_iter(slots_per_epoch) {
            slots.push(slot);
        }

        assert_eq!(slots.len(), slots_per_epoch as usize);

        for i in 0..slots_per_epoch {
            assert_eq!(Slot::from(i), slots[i as usize])
        }
    }

    #[test]
    fn max_epoch_ssz() {
        let max_epoch = Epoch::max_value();
        assert_eq!(
            &max_epoch.as_ssz_bytes(),
            &[255, 255, 255, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            max_epoch,
            Epoch::from_ssz_bytes(&max_epoch.as_ssz_bytes()).unwrap()
        );
    }
}
