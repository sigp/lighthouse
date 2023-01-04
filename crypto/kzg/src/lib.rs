mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};
pub use c_kzg::bytes_to_g1;
pub use c_kzg::{
    Error as CKzgError, KZGSettings, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT,
    FIELD_ELEMENTS_PER_BLOB,
};
use std::path::PathBuf;

/// The consensus type `Blob` is generic over EthSpec, so it cannot be imported
/// in this crate without creating a cyclic dependency between the kzg and consensus/types crates.
/// So need to use a Vec here unless we think of a smarter way of doing this
type Blob = [u8; BYTES_PER_BLOB];

#[derive(Debug)]
pub enum Error {
    InvalidTrustedSetup(CKzgError),
    InvalidKzgCommitment(CKzgError),
    InvalidKzgProof(CKzgError),
    KzgVerificationFailed(CKzgError),
    InvalidLength(String),
    KzgProofComputationFailed(CKzgError),
    InvalidBlob(String),
}

/// A wrapper over a kzg library that holds the trusted setup parameters.
pub struct Kzg {
    trusted_setup: KZGSettings,
}

impl Kzg {
    pub fn new_from_file(file_path: PathBuf) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KZGSettings::load_trusted_setup_file(file_path)
                .map_err(Error::InvalidTrustedSetup)?,
        })
    }

    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KZGSettings::load_trusted_setup(
                trusted_setup.g1_points,
                trusted_setup.g2_points,
            )
            .map_err(Error::InvalidTrustedSetup)?,
        })
    }

    pub fn compute_aggregate_kzg_proof(&self, blobs: &[Blob]) -> Result<KzgProof, Error> {
        c_kzg::KZGProof::compute_aggregate_kzg_proof(blobs, &self.trusted_setup)
            .map_err(Error::KzgProofComputationFailed)
            .map(|proof| KzgProof(proof.to_bytes()))
    }

    pub fn verify_aggregate_kzg_proof(
        &self,
        blobs: &[Blob],
        expected_kzg_commitments: &[KzgCommitment],
        kzg_aggregated_proof: KzgProof,
    ) -> Result<bool, Error> {
        if blobs.len() != expected_kzg_commitments.len() {
            return Err(Error::InvalidLength(
                "blobs and expected_kzg_commitments should be of same size".to_string(),
            ));
        }
        let commitments = expected_kzg_commitments
            .into_iter()
            .map(|comm| {
                c_kzg::KZGCommitment::from_bytes(&comm.0).map_err(Error::InvalidKzgCommitment)
            })
            .collect::<Result<Vec<c_kzg::KZGCommitment>, Error>>()?;
        let proof =
            c_kzg::KZGProof::from_bytes(&kzg_aggregated_proof.0).map_err(Error::InvalidKzgProof)?;
        proof
            .verify_aggregate_kzg_proof(blobs, &commitments, &self.trusted_setup)
            .map_err(Error::InvalidKzgProof)
    }

    pub fn blob_to_kzg_commitment(&self, blob: Blob) -> KzgCommitment {
        KzgCommitment(
            c_kzg::KZGCommitment::blob_to_kzg_commitment(blob, &self.trusted_setup).to_bytes(),
        )
    }
}
