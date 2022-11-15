mod kzg_commitment;
mod kzg_proof;

use std::path::PathBuf;

use c_kzg::{Error as CKzgError, KZGSettings};

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof};

#[derive(Debug)]
pub enum Error {
    InvalidTrustedSetup(CKzgError),
}

pub struct Kzg {
    _trusted_setup: KZGSettings,
}

impl Kzg {
    pub fn new_from_file(file_path: PathBuf) -> Result<Self, Error> {
        Ok(Self {
            _trusted_setup: KZGSettings::load_trusted_setup(file_path)
                .map_err(|e| Error::InvalidTrustedSetup(e))?,
        })
    }

    pub fn verify_aggregate_kzg_proof() {}

    pub fn blob_to_kzg_commitment() {}
}
