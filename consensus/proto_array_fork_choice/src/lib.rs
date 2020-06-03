mod error;
pub mod fork_choice_test_definition;
mod proto_array;
mod proto_array_fork_choice;
mod ssz_container;

pub use crate::proto_array_fork_choice::{Block, ProtoArrayForkChoice};
pub use error::Error;

pub mod core {
    pub use super::proto_array::ProtoArray;
}
