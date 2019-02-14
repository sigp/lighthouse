// Copyright 2019 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::slot_epoch::{Epoch, Slot};
use serde_derive::Serialize;
use slog;
use ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
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

// need to truncate for some fork-choice algorithms
macro_rules! impl_into_u32 {
    ($main: ident) => {
        impl Into<u32> for $main {
            fn into(self) -> u32 {
                self.0 as u32
            }
        }

        impl $main {
            pub fn as_u32(&self) -> u32 {
                self.0 as u32
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

            pub fn saturating_add<T: Into<$type>>(&self, other: T) -> $type {
                *self + other.into()
            }

            pub fn checked_div<T: Into<$type>>(&self, rhs: T) -> Option<$type> {
                let rhs: $type = rhs.into();
                if rhs == 0 {
                    None
                } else {
                    Some(*self / rhs)
                }
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

        impl slog::Value for $type {
            fn serialize(
                &self,
                record: &slog::Record,
                key: slog::Key,
                serializer: &mut slog::Serializer,
            ) -> slog::Result {
                self.0.serialize(record, key, serializer)
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
    };
}

macro_rules! impl_hash {
    ($type: ident) => {
        // Implemented to stop clippy lint:
        // https://rust-lang.github.io/rust-clippy/master/index.html#derive_hash_xor_eq
        impl Hash for $type {
            fn hash<H: Hasher>(&self, state: &mut H) {
                ssz_encode(self).hash(state)
            }
        }
    };
}

macro_rules! impl_common {
    ($type: ident) => {
        impl_from_into_u64!($type);
        impl_from_into_usize!($type);
        impl_math_between!($type, $type);
        impl_math_between!($type, u64);
        impl_math!($type);
        impl_display!($type);
        impl_ssz!($type);
        impl_hash!($type);
    };
}
/// Beacon block height, effectively `Slot/GENESIS_START_BLOCK`.
#[derive(Eq, Debug, Clone, Copy, Default, Serialize)]
pub struct SlotHeight(u64);

impl_common!(SlotHeight);
impl_into_u32!(SlotHeight); // SlotHeight can be converted to u32

impl SlotHeight {
    pub fn new(slot: u64) -> SlotHeight {
        SlotHeight(slot)
    }

    pub fn slot(self, genesis_slot: Slot) -> Slot {
        Slot::from(self.0.saturating_add(genesis_slot.as_u64()))
    }

    pub fn epoch(self, genesis_slot: u64, epoch_length: u64) -> Epoch {
        Epoch::from(self.0.saturating_add(genesis_slot) / epoch_length)
    }

    pub fn max_value() -> SlotHeight {
        SlotHeight(u64::max_value())
    }
}
