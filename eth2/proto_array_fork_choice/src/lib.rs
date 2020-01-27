mod error;
mod proto_array;
mod proto_array_fork_choice;
mod ssz_container;

pub use crate::proto_array_fork_choice::ProtoArrayForkChoice;
pub use error::Error;

pub mod core {
    pub use super::proto_array::ProtoArray;
}
