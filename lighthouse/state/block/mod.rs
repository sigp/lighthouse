extern crate blake2_rfc;

use super::attestation_record;
use super::common;
use super::db;
use super::ssz;
use super::utils;

mod structs;
mod ssz_block;
pub mod validation;

pub use self::structs::Block;
pub use self::ssz_block::{
    SszBlock,
    SszBlockError,
};
