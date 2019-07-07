#[macro_use]
mod impl_bitfield_fns;
mod bit_list;
mod bit_vector;
mod fixed_vector;
mod variable_list;

use impl_bitfield_fns::reverse_bit_order;

pub use bit_list::BitList;
pub use bit_vector::BitVector;
pub use fixed_vector::FixedVector;
pub use typenum;
pub use variable_list::VariableList;

/// Returned when an item encounters an error.
#[derive(PartialEq, Debug)]
pub enum Error {
    InvalidLength { i: usize, len: usize },
    OutOfBounds { i: usize, len: usize },
}
