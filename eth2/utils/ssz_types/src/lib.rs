mod bitfield;
mod fixed_vector;
mod variable_list;

pub use bitfield::{BitList, BitVector};
pub use fixed_vector::FixedVector;
pub use typenum;
pub use variable_list::VariableList;

/// Returned when a variable-length item encounters an error.
#[derive(PartialEq, Debug)]
pub enum VariableSizedError {
    /// The operation would cause the maximum length to be exceeded.
    ExceedsMaxLength {
        len: usize,
        max_len: usize,
    },
    OutOfBounds {
        i: usize,
        len: usize,
    },
}

/// Returned when a fixed-length item encounters an error.
#[derive(PartialEq, Debug)]
pub enum FixedSizedError {
    /// The operation would create an item of an invalid size.
    InvalidLength {
        i: usize,
        len: usize,
    },
    OutOfBounds {
        i: usize,
        len: usize,
    },
}
