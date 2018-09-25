mod validate_ssz_block;
#[cfg(test)]
mod tests;

use super::attestation_record;
use super::Block;
use super::SszBlock;
use super::db;
use super::ssz;
use super::utils;

use super::common::maps::{
    AttesterMap,
    ProposerMap,
};
pub use self::validate_ssz_block::{
    validate_ssz_block,
    SszBlockValidationError,
    BlockStatus,
};
