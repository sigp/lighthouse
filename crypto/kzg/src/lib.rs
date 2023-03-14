mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};
use c_kzg::Bytes48;
pub use c_kzg::{
    Blob, Error as CKzgError, KZGSettings, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT,
    FIELD_ELEMENTS_PER_BLOB,
};
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    InvalidTrustedSetup(CKzgError),
    InvalidKzgProof(CKzgError),
    InvalidBytes(CKzgError),
    KzgProofComputationFailed(CKzgError),
    InvalidBlob(CKzgError),
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

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        c_kzg::KZGProof::compute_blob_kzg_proof(blob, kzg_commitment.into(), &self.trusted_setup)
            .map_err(Error::KzgProofComputationFailed)
            .map(|proof| KzgProof(proof.to_bytes().into_inner()))
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        c_kzg::KZGProof::verify_blob_kzg_proof(
            blob,
            kzg_commitment.into(),
            kzg_proof.into(),
            &self.trusted_setup,
        )
        .map_err(Error::InvalidKzgProof)
    }

    /// Verify a batch of blob commitment proof triplets.
    ///
    /// Note: This method is slightly faster than calling `Self::verify_blob_kzg_proof` in a loop sequentially.
    /// TODO(pawan): test performance against a parallelized rayon impl.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        kzg_commitments: &[KzgCommitment],
        kzg_proofs: &[KzgProof],
    ) -> Result<bool, Error> {
        let commitments_bytes = kzg_commitments
            .iter()
            .map(|comm| Bytes48::from_bytes(&comm.0))
            .collect::<Result<Vec<Bytes48>, _>>()
            .map_err(Error::InvalidBytes)?;

        let proofs_bytes = kzg_proofs
            .iter()
            .map(|proof| Bytes48::from_bytes(&proof.0))
            .collect::<Result<Vec<Bytes48>, _>>()
            .map_err(Error::InvalidBytes)?;
        c_kzg::KZGProof::verify_blob_kzg_proof_batch(
            blobs,
            &commitments_bytes,
            &proofs_bytes,
            &self.trusted_setup,
        )
        .map_err(Error::InvalidKzgProof)
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: Blob) -> Result<KzgCommitment, Error> {
        c_kzg::KZGCommitment::blob_to_kzg_commitment(blob, &self.trusted_setup)
            .map_err(Error::InvalidBlob)
            .map(|com| KzgCommitment(com.to_bytes().into_inner()))
    }
}
