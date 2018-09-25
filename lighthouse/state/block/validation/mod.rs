mod validate_ssz_block;

use super::attestation_record;
use super::SszBlock;
use super::Logger;
use super::db;
use super::ssz;
use super::utils;

use super::common::maps::{
    AttesterMap,
    ProposerMap,
};
pub use self::validate_ssz_block::{
    validate_ssz_block,
    SszBlockValidationError
};
