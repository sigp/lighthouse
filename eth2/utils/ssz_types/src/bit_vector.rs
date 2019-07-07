use super::*;
use crate::{impl_bitfield_fns, reverse_bit_order, Error};
use bit_vec::BitVec as Bitfield;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::cmp;
use std::marker::PhantomData;
use typenum::Unsigned;

/// Emulates a SSZ `Bitvector`.
///
/// An ordered, heap-allocated, fixed-length, collection of `bool` values, with `N` values.
///
/// ## Notes
///
/// Considering this struct is backed by bytes, errors may be raised when attempting to decode
/// bytes into a `BitVector<N>` where `N` is not a multiple of 8. It is advised to always set `N` to
/// a multiple of 8.
///
/// ## Example
/// ```
/// use ssz_types::{BitVector, typenum};
///
/// let mut bitvec: BitVector<typenum::U8> = BitVector::new();
///
/// assert_eq!(bitvec.len(), 8);
///
/// for i in 0..8 {
///     assert_eq!(bitvec.get(i).unwrap(), false);  // Defaults to false.
/// }
///
/// assert!(bitvec.get(8).is_err());  // Cannot get out-of-bounds.
///
/// assert!(bitvec.set(7, true).is_ok());
/// assert!(bitvec.set(8, true).is_err());  // Cannot set out-of-bounds.
/// ```
#[derive(Debug, Clone)]
pub struct BitVector<N> {
    bitfield: Bitfield,
    _phantom: PhantomData<N>,
}

impl_bitfield_fns!(BitVector);

impl<N: Unsigned> BitVector<N> {
    /// Create a new bitfield.
    pub fn new() -> Self {
        Self::with_capacity(Self::capacity()).expect("Capacity must be correct")
    }

    fn capacity() -> usize {
        N::to_usize()
    }

    fn validate_length(len: usize) -> Result<(), Error> {
        let fixed_len = N::to_usize();

        if len > fixed_len {
            Err(Error::InvalidLength {
                i: len,
                len: fixed_len,
            })
        } else {
            Ok(())
        }
    }
}
