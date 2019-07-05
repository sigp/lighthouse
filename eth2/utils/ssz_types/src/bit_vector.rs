use crate::bitfield::{Bitfield, Error};
use crate::{FixedSizedError, VariableSizedError};
use std::marker::PhantomData;
use typenum::Unsigned;

/// Provides a common `impl` for structs that wrap a `Bitfield`.
macro_rules! common_impl {
    ($name: ident, $error: ident) => {
        impl<N: Unsigned> $name<N> {
            /// Create a new bitfield with the given length `initial_len` and all values set to `bit`.
            ///
            /// Note: if `initial_len` is not a multiple of 8, the remaining bits will be set to `false`
            /// regardless of `bit`.
            pub fn from_elem(initial_len: usize, bit: bool) -> Result<Self, $error> {
                let bitfield = Bitfield::from_elem(initial_len, bit);
                Self::from_bitfield(bitfield)
            }

            /// Create a new BitList using the supplied `bytes` as input
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $error> {
                let bitfield = Bitfield::from_bytes(bytes);
                Self::from_bitfield(bitfield)
            }

            /// Returns a vector of bytes representing the bitfield
            pub fn to_bytes(&self) -> Vec<u8> {
                self.bitfield.to_bytes()
            }

            /// Read the value of a bit.
            ///
            /// If the index is in bounds, then result is Ok(value) where value is `true` if the bit is 1 and `false` if the bit is 0.
            /// If the index is out of bounds, we return an error to that extent.
            pub fn get(&self, i: usize) -> Result<bool, Error> {
                self.bitfield.get(i)
            }

            fn capacity() -> usize {
                N::to_usize()
            }

            /// Set the value of a bit.
            ///
            /// Returns an `Err` if `i` is outside of the maximum permitted length.
            pub fn set(&mut self, i: usize, value: bool) -> Result<(), VariableSizedError> {
                if i < Self::capacity() {
                    self.bitfield.set(i, value);
                    Ok(())
                } else {
                    Err(VariableSizedError::ExceedsMaxLength {
                        len: Self::capacity() + 1,
                        max_len: Self::capacity(),
                    })
                }
            }

            /// Returns the number of bits in this bitfield.
            pub fn len(&self) -> usize {
                self.bitfield.len()
            }

            /// Returns true if `self.len() == 0`
            pub fn is_empty(&self) -> bool {
                self.bitfield.is_empty()
            }

            /// Returns true if all bits are set to 0.
            pub fn is_zero(&self) -> bool {
                self.bitfield.is_zero()
            }

            /// Returns the number of bytes required to represent this bitfield.
            pub fn num_bytes(&self) -> usize {
                self.bitfield.num_bytes()
            }

            /// Returns the number of `1` bits in the bitfield
            pub fn num_set_bits(&self) -> usize {
                self.bitfield.num_set_bits()
            }
        }
    };
}

/// Emulates a SSZ `Bitvector`.
///
/// An ordered, heap-allocated, fixed-length, collection of `bool` values, with `N` values.
pub struct BitVector<N> {
    bitfield: Bitfield,
    _phantom: PhantomData<N>,
}

common_impl!(BitVector, FixedSizedError);

impl<N: Unsigned> BitVector<N> {
    /// Create a new bitfield.
    pub fn new() -> Self {
        Self {
            bitfield: Bitfield::with_capacity(N::to_usize()),
            _phantom: PhantomData,
        }
    }

    fn from_bitfield(bitfield: Bitfield) -> Result<Self, FixedSizedError> {
        if bitfield.len() != Self::capacity() {
            Err(FixedSizedError::InvalidLength {
                len: bitfield.len(),
                fixed_len: Self::capacity(),
            })
        } else {
            Ok(Self {
                bitfield,
                _phantom: PhantomData,
            })
        }
    }
}

/// Emulates a SSZ `Bitlist`.
///
/// An ordered, heap-allocated, variable-length, collection of `bool` values, limited to `N`
/// values.
pub struct BitList<N> {
    bitfield: Bitfield,
    _phantom: PhantomData<N>,
}

common_impl!(BitList, VariableSizedError);

impl<N: Unsigned> BitList<N> {
    /// Create a new, empty BitList.
    pub fn new() -> Self {
        Self {
            bitfield: Bitfield::default(),
            _phantom: PhantomData,
        }
    }

    /// Create a new BitList list with `initial_len` bits all set to `false`.
    pub fn with_capacity(initial_len: usize) -> Result<Self, VariableSizedError> {
        Self::from_elem(initial_len, false)
    }

    /// The maximum possible number of bits.
    pub fn max_len() -> usize {
        N::to_usize()
    }

    fn from_bitfield(bitfield: Bitfield) -> Result<Self, VariableSizedError> {
        if bitfield.len() > Self::max_len() {
            Err(VariableSizedError::ExceedsMaxLength {
                len: bitfield.len(),
                max_len: Self::max_len(),
            })
        } else {
            Ok(Self {
                bitfield,
                _phantom: PhantomData,
            })
        }
    }

    /// Compute the intersection (binary-and) of this bitfield with another
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn intersection(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let bitfield = self.bitfield.intersection(&other.bitfield);
        Self::from_bitfield(bitfield).expect(
            "An intersection of two same-sized sets cannot be larger than one of the initial sets",
        )
    }

    /// Like `intersection` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn intersection_inplace(&mut self, other: &Self) {
        self.bitfield.intersection_inplace(&other.bitfield);
    }

    /// Compute the union (binary-or) of this bitfield with another. Lengths must match.
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn union(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let bitfield = self.bitfield.union(&other.bitfield);
        Self::from_bitfield(bitfield)
            .expect("A union of two same-sized sets cannot be larger than one of the initial sets")
    }

    /// Like `union` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn union_inplace(&mut self, other: &Self) {
        self.bitfield.union_inplace(&other.bitfield)
    }

    /// Compute the difference (binary-minus) of this bitfield with another. Lengths must match.
    ///
    /// Computes `self - other`.
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn difference(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let bitfield = self.bitfield.difference(&other.bitfield);
        Self::from_bitfield(bitfield).expect(
            "A difference of two same-sized sets cannot be larger than one of the initial sets",
        )
    }

    /// Like `difference` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn difference_inplace(&mut self, other: &Self) {
        self.bitfield.difference_inplace(&other.bitfield)
    }
}
