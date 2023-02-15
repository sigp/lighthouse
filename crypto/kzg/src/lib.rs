mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};
pub use c_kzg::{
    Blob, Error as CKzgError, KZGSettings, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT,
    FIELD_ELEMENTS_PER_BLOB,
};
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    InvalidTrustedSetup(CKzgError),
    InvalidKzgProof(CKzgError),
    InvalidLength(String),
    KzgProofComputationFailed(CKzgError),
    InvalidBlob(String),
}

/// A wrapper over a kzg library that holds the trusted setup parameters.
pub struct Kzg {
    trusted_setup: KZGSettings,
}

impl Kzg {
    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    ///
    /// The number of G1 points should be equal to FIELD_ELEMENTS_PER_BLOB
    /// Note: this number changes based on the preset values.
    /// The number of G2 points should be equal to 65.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KZGSettings::load_trusted_setup(
                trusted_setup.g1_points(),
                trusted_setup.g2_points(),
            )
            .map_err(Error::InvalidTrustedSetup)?,
        })
    }

    /// Loads a trusted setup given the path to the file containing the trusted setup values.
    /// The format is specified in `c_kzg::KzgSettings::load_trusted_setup_file`.
    ///
    /// Note: This function will likely be deprecated. Use `Kzg::new_from_trusted_setup` instead.
    #[deprecated]
    pub fn new_from_file(file_path: PathBuf) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KZGSettings::load_trusted_setup_file(file_path)
                .map_err(Error::InvalidTrustedSetup)?,
        })
    }

    /// Compute the aggregated kzg proof given an array of blobs.
    pub fn compute_aggregate_kzg_proof(&self, blobs: &[Blob]) -> Result<KzgProof, Error> {
        c_kzg::KZGProof::compute_aggregate_kzg_proof(blobs, &self.trusted_setup)
            .map_err(Error::KzgProofComputationFailed)
            .map(|proof| KzgProof(proof.to_bytes()))
    }

    /// Verify an aggregate kzg proof given the blobs that generated the proof, the kzg commitments
    /// and the kzg proof.
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
            .iter()
            .map(|comm| comm.0.into())
            .collect::<Vec<c_kzg::KZGCommitment>>();
        let proof: c_kzg::KZGProof = kzg_aggregated_proof.0.into();
        proof
            .verify_aggregate_kzg_proof(blobs, &commitments, &self.trusted_setup)
            .map_err(Error::InvalidKzgProof)
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: Blob) -> KzgCommitment {
        KzgCommitment(
            c_kzg::KZGCommitment::blob_to_kzg_commitment(blob, &self.trusted_setup).to_bytes(),
        )
    }
}
