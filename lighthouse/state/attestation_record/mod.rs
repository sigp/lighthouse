use super::bls;
use super::common;
use super::db;
use super::ssz;
use super::utils;


mod structs;
mod ssz_splitter;
mod validation;

pub use self::structs::{
    AttestationRecord,
    MIN_SSZ_ATTESTION_RECORD_LENGTH,
};
pub use self::ssz_splitter::{
    split_all_attestations,
    split_one_attestation,
    AttestationSplitError,
};
pub use self::validation::{
    validate_attestation,
    AttestationValidationError,
};
