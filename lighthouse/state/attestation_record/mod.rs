use super::bls;
use super::common;
use super::db;
use super::ssz;
use super::utils;


mod attestation_record;
mod ssz_splitter;
pub mod validation;

pub use self::attestation_record::{
    AttestationRecord,
    MIN_SSZ_ATTESTION_RECORD_LENGTH,
};
pub use self::ssz_splitter::{
    split_all_attestations,
    split_one_attestation,
    AttestationSplitError,
};
