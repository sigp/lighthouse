extern crate bls;
extern crate db;
extern crate hashing;
extern crate ssz;
extern crate ssz_helpers;
extern crate types;

#[macro_use]
mod macros;
mod enums;
mod validate_for_block;
mod validate_for_state;
mod validate_signature;

pub use enums::{Invalid, Outcome, Error};
pub use validate_for_block::validate_attestation_for_block;
pub use validate_for_state::validate_attestation_data_for_state;
pub use validate_signature::validate_attestation_signature;
