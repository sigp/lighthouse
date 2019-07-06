mod bitfield;
mod fixed_vector;
mod variable_list;

pub use bitfield::{BitList, BitVector};
pub use fixed_vector::FixedVector;
pub use typenum;
pub use variable_list::VariableList;

/// Returned when an item encounters an error.
#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidLength { i: usize, len: usize },
    OutOfBounds { i: usize, len: usize },
}
