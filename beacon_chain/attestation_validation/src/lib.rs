extern crate bls;
extern crate db;
extern crate hashing;
extern crate ssz;
extern crate types;

#[macro_use]
mod macros;

mod block_inclusion;
mod enums;
mod justified_block;
mod justified_slot;
mod shard_block;
mod signature;

pub use crate::enums::{Invalid, Outcome, Error};
pub use crate::block_inclusion::validate_attestation_for_block;
pub use crate::justified_slot::validate_attestation_justified_slot;
pub use crate::justified_block::validate_attestation_justified_block_hash;
pub use crate::signature::validate_attestation_signature;
pub use crate::shard_block::validate_attestation_data_shard_block_hash;
