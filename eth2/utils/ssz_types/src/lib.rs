//! Provides types with unique properties required for SSZ serialization and Merklization:
//!
//! - `FixedVector`: A heap-allocated list with a size that is fixed at compile time.
//! - `VariableList`: A heap-allocated list that cannot grow past a type-level maximum length.
//! - `BitList`: A heap-allocated bitfield that with a type-level _maximum_ length.
//! - `BitVector`: A heap-allocated bitfield that with a type-level _fixed__ length.
//!
//! These structs are required as SSZ serialization and Merklization rely upon type-level lengths
//! for padding and verification.
//!
//! ## Example
//! ```
//! use ssz_types::*;
//!
//! pub struct Example {
//!     bit_vector: BitVector<typenum::U8>,
//!     bit_list: BitList<typenum::U8>,
//!     variable_list: VariableList<u64, typenum::U8>,
//!     fixed_vector: FixedVector<u64, typenum::U8>,
//! }
//!
//! let mut example = Example {
//!     bit_vector: Bitfield::new(),
//!     bit_list: Bitfield::with_capacity(4).unwrap(),
//!     variable_list: <_>::from(vec![0, 1]),
//!     fixed_vector: <_>::from(vec![2, 3]),
//! };
//!
//! assert_eq!(example.bit_vector.len(), 8);
//! assert_eq!(example.bit_list.len(), 4);
//! assert_eq!(&example.variable_list[..], &[0, 1]);
//! assert_eq!(&example.fixed_vector[..], &[2, 3, 0, 0, 0, 0, 0, 0]);
//!
//! ```

#[macro_use]
mod bitfield;
mod fixed_vector;
mod variable_list;

pub use bitfield::{BitList, BitVector, Bitfield};
pub use fixed_vector::FixedVector;
pub use typenum;
pub use variable_list::VariableList;

pub mod length {
    pub use crate::bitfield::{Fixed, Variable};
}

/// Returned when an item encounters an error.
#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidLength { i: usize, len: usize },
    OutOfBounds { i: usize, len: usize },
}
