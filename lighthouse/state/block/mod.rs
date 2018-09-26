extern crate blake2_rfc;

use super::ssz;
use super::utils;
use super::attestation_record;

mod structs;
mod ssz_block;

pub use self::structs::Block;
pub use self::ssz_block::SszBlock;
