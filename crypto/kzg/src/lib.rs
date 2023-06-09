mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

use std::ops::Deref;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};
pub use c_kzg::{Bytes32, Bytes48};

#[derive(Debug)]
pub enum Error {
    InvalidTrustedSetup(CryptoError),
    InvalidKzgProof(CryptoError),
    InvalidBytes(CryptoError),
    KzgProofComputationFailed(CryptoError),
    InvalidBlob(CryptoError),
}

#[derive(Debug)]
pub enum CryptoError {
    CKzg(c_kzg::Error),
    CKzgMin(c_kzg_min::Error),
}

impl From<c_kzg::Error> for CryptoError {
    fn from(e: c_kzg::Error) -> Self {
        Self::CKzg(e)
    }
}

impl From<c_kzg_min::Error> for CryptoError {
    fn from(e: c_kzg_min::Error) -> Self {
        Self::CKzgMin(e)
    }
}

pub trait KzgPreset {
    type KzgSettings;
    type Blob;
    type Bytes32: From<[u8; 32]> + Deref<Target = [u8; 32]>;
    type Bytes48: From<KzgCommitment> + From<KzgProof>;
    type Error: Into<CryptoError>;

    const BYTES_PER_BLOB: usize;
    const BYTES_PER_FIELD_ELEMENT: usize;
    const FIELD_ELEMENTS_PER_BLOB: usize;

    fn bytes32_in(bytes: Bytes32) -> Self::Bytes32 {
        let bytes: [u8; 32] = *bytes;
        Self::Bytes32::from(bytes)
    }

    fn bytes32_out(bytes: Self::Bytes32) -> Bytes32 {
        let bytes: [u8; 32] = *bytes;
        Bytes32::from(bytes)
    }

    fn load_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self::KzgSettings, CryptoError>;

    fn compute_blob_kzg_proof(
        blob: Self::Blob,
        kzg_commitment: KzgCommitment,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<KzgProof, CryptoError>;

    fn verify_blob_kzg_proof(
        blob: Self::Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, CryptoError>;

    fn verify_blob_kzg_proof_batch(
        blobs: &[Self::Blob],
        commitments_bytes: &[Self::Bytes48],
        proofs_bytes: &[Self::Bytes48],
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, CryptoError>;

    fn blob_to_kzg_commitment(
        blob: Self::Blob,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<KzgCommitment, CryptoError>;

    fn compute_kzg_proof(
        blob: Self::Blob,
        z: Self::Bytes32,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<(KzgProof, Self::Bytes32), CryptoError>;

    fn verify_kzg_proof(
        kzg_commitment: KzgCommitment,
        z: Self::Bytes32,
        y: Self::Bytes32,
        kzg_proof: KzgProof,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, CryptoError>;
}

macro_rules! implement_kzg_preset {
    ($preset_type:ident, $module_name:ident) => {
        impl KzgPreset for $preset_type {
            type KzgSettings = $module_name::KzgSettings;
            type Blob = $module_name::Blob;
            type Bytes32 = $module_name::Bytes32;
            type Bytes48 = $module_name::Bytes48;
            type Error = $module_name::Error;

            const BYTES_PER_BLOB: usize = $module_name::BYTES_PER_BLOB;
            const BYTES_PER_FIELD_ELEMENT: usize = $module_name::BYTES_PER_FIELD_ELEMENT;
            const FIELD_ELEMENTS_PER_BLOB: usize = $module_name::FIELD_ELEMENTS_PER_BLOB;

            fn load_trusted_setup(
                trusted_setup: TrustedSetup,
            ) -> Result<Self::KzgSettings, CryptoError> {
                $module_name::KzgSettings::load_trusted_setup(
                    trusted_setup.g1_points(),
                    trusted_setup.g2_points(),
                )
                .map_err(CryptoError::from)
            }

            fn compute_blob_kzg_proof(
                blob: Self::Blob,
                kzg_commitment: KzgCommitment,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<KzgProof, CryptoError> {
                $module_name::KzgProof::compute_blob_kzg_proof(
                    blob,
                    kzg_commitment.into(),
                    trusted_setup,
                )
                .map(|proof| KzgProof(proof.to_bytes().into_inner()))
                .map_err(CryptoError::from)
            }

            fn verify_blob_kzg_proof(
                blob: Self::Blob,
                kzg_commitment: KzgCommitment,
                kzg_proof: KzgProof,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, CryptoError> {
                $module_name::KzgProof::verify_blob_kzg_proof(
                    blob,
                    kzg_commitment.into(),
                    kzg_proof.into(),
                    trusted_setup,
                )
                .map_err(CryptoError::from)
            }

            fn verify_blob_kzg_proof_batch(
                blobs: &[Self::Blob],
                commitments_bytes: &[Self::Bytes48],
                proofs_bytes: &[Self::Bytes48],
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, CryptoError> {
                $module_name::KzgProof::verify_blob_kzg_proof_batch(
                    blobs,
                    commitments_bytes,
                    proofs_bytes,
                    trusted_setup,
                )
                .map_err(CryptoError::from)
            }

            fn blob_to_kzg_commitment(
                blob: Self::Blob,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<KzgCommitment, CryptoError> {
                $module_name::KzgCommitment::blob_to_kzg_commitment(blob, trusted_setup)
                    .map(|com| KzgCommitment(com.to_bytes().into_inner()))
                    .map_err(CryptoError::from)
            }

            fn compute_kzg_proof(
                blob: Self::Blob,
                z: Self::Bytes32,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<(KzgProof, Self::Bytes32), CryptoError> {
                $module_name::KzgProof::compute_kzg_proof(blob, z, trusted_setup)
                    .map(|(proof, y)| (KzgProof(proof.to_bytes().into_inner()), y))
                    .map_err(CryptoError::from)
            }

            fn verify_kzg_proof(
                kzg_commitment: KzgCommitment,
                z: Self::Bytes32,
                y: Self::Bytes32,
                kzg_proof: KzgProof,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, CryptoError> {
                $module_name::KzgProof::verify_kzg_proof(
                    kzg_commitment.into(),
                    z,
                    y,
                    kzg_proof.into(),
                    trusted_setup,
                )
                .map_err(CryptoError::from)
            }
        }
    };
}

pub struct MainnetKzgPreset;
pub struct MinimalKzgPreset;

implement_kzg_preset!(MainnetKzgPreset, c_kzg);
implement_kzg_preset!(MinimalKzgPreset, c_kzg_min);

/// A wrapper over a kzg library that holds the trusted setup parameters.
#[derive(Debug)]
pub struct Kzg<P: KzgPreset> {
    trusted_setup: P::KzgSettings,
}

impl<P: KzgPreset> Kzg<P> {
    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    ///
    /// The number of G1 points should be equal to FIELD_ELEMENTS_PER_BLOB
    /// Note: this number changes based on the preset values.
    /// The number of G2 points should be equal to 65.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: P::load_trusted_setup(trusted_setup)
                .map_err(Error::InvalidTrustedSetup)?,
        })
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: P::Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        P::compute_blob_kzg_proof(blob, kzg_commitment, &self.trusted_setup)
            .map_err(Error::KzgProofComputationFailed)
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: P::Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        P::verify_blob_kzg_proof(blob, kzg_commitment, kzg_proof, &self.trusted_setup)
            .map_err(Error::InvalidKzgProof)
    }

    /// Verify a batch of blob commitment proof triplets.
    ///
    /// Note: This method is slightly faster than calling `Self::verify_blob_kzg_proof` in a loop sequentially.
    /// TODO(pawan): test performance against a parallelized rayon impl.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[P::Blob],
        kzg_commitments: &[KzgCommitment],
        kzg_proofs: &[KzgProof],
    ) -> Result<bool, Error> {
        let commitments_bytes = kzg_commitments
            .iter()
            .map(|comm| P::Bytes48::from(*comm))
            .collect::<Vec<_>>();

        let proofs_bytes = kzg_proofs
            .iter()
            .map(|proof| P::Bytes48::from(*proof))
            .collect::<Vec<_>>();

        P::verify_blob_kzg_proof_batch(
            blobs,
            &commitments_bytes,
            &proofs_bytes,
            &self.trusted_setup,
        )
        .map_err(Error::InvalidKzgProof)
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: P::Blob) -> Result<KzgCommitment, Error> {
        P::blob_to_kzg_commitment(blob, &self.trusted_setup).map_err(Error::InvalidBlob)
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: P::Blob,
        z: Bytes32,
    ) -> Result<(KzgProof, Bytes32), Error> {
        P::compute_kzg_proof(blob, P::bytes32_in(z), &self.trusted_setup)
            .map_err(Error::KzgProofComputationFailed)
            .map(|(proof, y)| (proof, P::bytes32_out(y)))
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KzgCommitment,
        z: Bytes32,
        y: Bytes32,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        P::verify_kzg_proof(
            kzg_commitment,
            P::bytes32_in(z),
            P::bytes32_in(y),
            kzg_proof,
            &self.trusted_setup,
        )
        .map_err(Error::InvalidKzgProof)
    }
}
