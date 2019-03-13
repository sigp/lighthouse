use crate::slot_height::SlotHeight;
/// The `Slot` and `Epoch` types are defined as newtypes over u64 to enforce type-safety between
/// the two types.
///
/// `Slot` and `Epoch` have implementations which permit conversion, comparison and math operations
/// between each and `u64`, however specifically not between each other.
///
/// All math operations on `Slot` and `Epoch` are saturating, they never wrap.
///
/// It would be easy to define `PartialOrd` and other traits generically across all types which
/// implement `Into<u64>`, however this would allow operations between `Slots` and `Epochs` which
/// may lead to programming errors which are not detected by the compiler.
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use slog;
use ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::Iterator;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

#[derive(Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Slot(u64);

#[derive(Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Epoch(u64);

impl_common!(Slot);
impl_common!(Epoch);

impl Slot {
    pub fn new(slot: u64) -> Slot {
        Slot(slot)
    }

    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch::from(self.0 / slots_per_epoch)
    }

    pub fn height(self, genesis_slot: Slot) -> SlotHeight {
        SlotHeight::from(self.0.saturating_sub(genesis_slot.as_u64()))
    }

    pub fn max_value() -> Slot {
        Slot(u64::max_value())
    }
}

impl Epoch {
    pub fn new(slot: u64) -> Epoch {
        Epoch(slot)
    }

    pub fn max_value() -> Epoch {
        Epoch(u64::max_value())
    }

    pub fn start_slot(self, slots_per_epoch: u64) -> Slot {
        Slot::from(self.0.saturating_mul(slots_per_epoch))
    }

    pub fn end_slot(self, slots_per_epoch: u64) -> Slot {
        Slot::from(
            self.0
                .saturating_add(1)
                .saturating_mul(slots_per_epoch)
                .saturating_sub(1),
        )
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
            self.current_iteration += 1;
            Some(start_slot + previous)
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
}
