use crate::slot_epoch::{Epoch, Slot};
use crate::test_utils::TestRandom;

use rand::RngCore;
use serde_derive::Serialize;
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

/// Beacon block height, effectively `Slot/GENESIS_START_BLOCK`.
#[derive(Eq, Debug, Clone, Copy, Default, Serialize)]
pub struct SlotHeight(u64);

impl_common!(SlotHeight);

impl SlotHeight {
    pub fn new(slot: u64) -> SlotHeight {
        SlotHeight(slot)
    }

    pub fn slot(self, genesis_slot: Slot) -> Slot {
        Slot::from(self.0.saturating_add(genesis_slot.as_u64()))
    }

    pub fn epoch(self, genesis_slot: u64, slots_per_epoch: u64) -> Epoch {
        Epoch::from(self.0.saturating_add(genesis_slot) / slots_per_epoch)
    }

    pub fn max_value() -> SlotHeight {
        SlotHeight(u64::max_value())
    }
}

#[cfg(test)]
mod slot_height_tests {
    use super::*;

    all_tests!(SlotHeight);
}
