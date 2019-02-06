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
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::iter::Iterator;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, Sub, SubAssign};

macro_rules! impl_from_into_u64 {
    ($main: ident) => {
        impl From<u64> for $main {
            fn from(n: u64) -> $main {
                $main(n)
            }
        }

        impl Into<u64> for $main {
            fn into(self) -> u64 {
                self.0
            }
        }

        impl $main {
            pub fn as_u64(&self) -> u64 {
                self.0
            }
        }
    };
}

macro_rules! impl_from_into_usize {
    ($main: ident) => {
        impl From<usize> for $main {
            fn from(n: usize) -> $main {
                $main(n as u64)
            }
        }

        impl Into<usize> for $main {
            fn into(self) -> usize {
                self.0 as usize
            }
        }

        impl $main {
            pub fn as_usize(&self) -> usize {
                self.0 as usize
            }
        }
    };
}

macro_rules! impl_math_between {
    ($main: ident, $other: ident) => {
        impl PartialOrd<$other> for $main {
            /// Utilizes `partial_cmp` on the underlying `u64`.
            fn partial_cmp(&self, other: &$other) -> Option<Ordering> {
                Some(self.0.cmp(&(*other).into()))
            }
        }

        impl PartialEq<$other> for $main {
            fn eq(&self, other: &$other) -> bool {
                let other: u64 = (*other).into();
                self.0 == other
            }
        }

        impl Add<$other> for $main {
            type Output = $main;

            fn add(self, other: $other) -> $main {
                $main::from(self.0.saturating_add(other.into()))
            }
        }

        impl AddAssign<$other> for $main {
            fn add_assign(&mut self, other: $other) {
                self.0 = self.0.saturating_add(other.into());
            }
        }

        impl Sub<$other> for $main {
            type Output = $main;

            fn sub(self, other: $other) -> $main {
                $main::from(self.0.saturating_sub(other.into()))
            }
        }

        impl SubAssign<$other> for $main {
            fn sub_assign(&mut self, other: $other) {
                self.0 = self.0.saturating_sub(other.into());
            }
        }

        impl Mul<$other> for $main {
            type Output = $main;

            fn mul(self, rhs: $other) -> $main {
                let rhs: u64 = rhs.into();
                $main::from(self.0.saturating_mul(rhs))
            }
        }

        impl MulAssign<$other> for $main {
            fn mul_assign(&mut self, rhs: $other) {
                let rhs: u64 = rhs.into();
                self.0 = self.0.saturating_mul(rhs)
            }
        }

        impl Div<$other> for $main {
            type Output = $main;

            fn div(self, rhs: $other) -> $main {
                let rhs: u64 = rhs.into();
                if rhs == 0 {
                    panic!("Cannot divide by zero-valued Slot/Epoch")
                }
                $main::from(self.0 / rhs)
            }
        }

        impl DivAssign<$other> for $main {
            fn div_assign(&mut self, rhs: $other) {
                let rhs: u64 = rhs.into();
                if rhs == 0 {
                    panic!("Cannot divide by zero-valued Slot/Epoch")
                }
                self.0 = self.0 / rhs
            }
        }

        impl Rem<$other> for $main {
            type Output = $main;

            fn rem(self, modulus: $other) -> $main {
                let modulus: u64 = modulus.into();
                $main::from(self.0 % modulus)
            }
        }
    };
}

macro_rules! impl_math {
    ($type: ident) => {
        impl $type {
            pub fn saturating_sub<T: Into<$type>>(&self, other: T) -> $type {
                *self - other.into()
            }

            pub fn is_power_of_two(&self) -> bool {
                self.0.is_power_of_two()
            }
        }

        impl Ord for $type {
            fn cmp(&self, other: &$type) -> Ordering {
                let other: u64 = (*other).into();
                self.0.cmp(&other)
            }
        }
    };
}

macro_rules! impl_display {
    ($type: ident) => {
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! impl_ssz {
    ($type: ident) => {
        impl Encodable for $type {
            fn ssz_append(&self, s: &mut SszStream) {
                s.append(&self.0);
            }
        }

        impl Decodable for $type {
            fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
                let (value, i) = <_>::ssz_decode(bytes, i)?;

                Ok(($type(value), i))
            }
        }

        impl TreeHash for $type {
            fn hash_tree_root(&self) -> Vec<u8> {
                let mut result: Vec<u8> = vec![];
                result.append(&mut self.0.hash_tree_root());
                hash(&result)
            }
        }

        impl<T: RngCore> TestRandom<T> for $type {
            fn random_for_test(rng: &mut T) -> Self {
                $type::from(u64::random_for_test(rng))
            }
        }
    };
}

#[derive(Eq, Debug, Clone, Copy, Default, Serialize, Hash)]
pub struct Slot(u64);

#[derive(Eq, Debug, Clone, Copy, Default, Serialize, Hash)]
pub struct Epoch(u64);

impl_from_into_u64!(Slot);
impl_from_into_usize!(Slot);
impl_math_between!(Slot, Slot);
impl_math_between!(Slot, u64);
impl_math!(Slot);
impl_display!(Slot);
impl_ssz!(Slot);

impl_from_into_u64!(Epoch);
impl_from_into_usize!(Epoch);
impl_math_between!(Epoch, Epoch);
impl_math_between!(Epoch, u64);
impl_math!(Epoch);
impl_display!(Epoch);
impl_ssz!(Epoch);

impl Slot {
    pub fn new(slot: u64) -> Slot {
        Slot(slot)
    }

    pub fn epoch(&self, epoch_length: u64) -> Epoch {
        Epoch::from(self.0 / epoch_length)
    }

    pub fn max_value() -> Slot {
        Slot(u64::max_value())
    }
}

impl Epoch {
    pub fn new(slot: u64) -> Epoch {
        Epoch(slot)
    }

    pub fn start_slot(&self, epoch_length: u64) -> Slot {
        Slot::from(self.0.saturating_mul(epoch_length))
    }

    pub fn end_slot(&self, epoch_length: u64) -> Slot {
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
