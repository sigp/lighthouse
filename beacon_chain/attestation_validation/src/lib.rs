extern crate bls;
extern crate db;
extern crate hashing;
extern crate ssz;
extern crate ssz_helpers;
extern crate types;

#[macro_use]
mod macros;

mod block_inclusion;
mod enums;
mod justified_block;
mod justified_slot;
mod shard_block;
mod signature;

pub use enums::{Invalid, Outcome, Error};
pub use block_inclusion::validate_attestation_for_block;
pub use justified_slot::validate_attestation_justified_slot;
pub use justified_block::validate_attestation_justified_block_hash;
pub use signature::validate_attestation_signature;
pub use shard_block::validate_attestation_data_shard_block_hash;
