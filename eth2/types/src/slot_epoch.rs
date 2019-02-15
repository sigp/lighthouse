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
use serde_derive::Serialize;
use slog;
use ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::Iterator;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

#[derive(Eq, Debug, Clone, Copy, Default, Serialize)]
pub struct Slot(u64);

#[derive(Eq, Debug, Clone, Copy, Default, Serialize)]
pub struct Epoch(u64);

impl_common!(Slot);
impl_common!(Epoch);

impl Slot {
    pub fn new(slot: u64) -> Slot {
        Slot(slot)
    }

    pub fn epoch(self, epoch_length: u64) -> Epoch {
        Epoch::from(self.0 / epoch_length)
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

    pub fn start_slot(self, epoch_length: u64) -> Slot {
        Slot::from(self.0.saturating_mul(epoch_length))
    }

    pub fn end_slot(self, epoch_length: u64) -> Slot {
        Slot::from(
            self.0
                .saturating_add(1)
                .saturating_mul(epoch_length)
                .saturating_sub(1),
        )
    }

    pub fn slot_iter(&self, epoch_length: u64) -> SlotIter {
        SlotIter {
            current: self.start_slot(epoch_length),
            epoch: self,
            epoch_length,
        }
    }
}

pub struct SlotIter<'a> {
    current: Slot,
    epoch: &'a Epoch,
    epoch_length: u64,
}

impl<'a> Iterator for SlotIter<'a> {
    type Item = Slot;

    fn next(&mut self) -> Option<Slot> {
        if self.current == self.epoch.end_slot(self.epoch_length) {
            None
        } else {
            let previous = self.current;
            self.current += 1;
            Some(previous)
        }
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

    all_tests!(Slot);
}

#[cfg(test)]
mod epoch_tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

    all_tests!(Epoch);
}
