mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;

pub use crate::{kzg_commitment::KzgCommitment, kzg_proof::KzgProof, trusted_setup::TrustedSetup};
pub use c_kzg::{Bytes32, Bytes48, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF};

#[derive(Debug)]
pub enum Error {
    InconsistentTrustedSetup,
    CKzgError(c_kzg::Error),
}

pub trait BlobTrait: Sized + Clone {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

pub enum KzgPresetId {
    Mainnet,
    Minimal,
}

impl FromStr for KzgPresetId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(KzgPresetId::Mainnet),
            "minimal" => Ok(KzgPresetId::Minimal),
            _ => Err(format!("Unknown eth spec: {}", s)),
        }
    }
}

impl From<c_kzg::Error> for Error {
    fn from(value: c_kzg::Error) -> Self {
        Self::CKzgError(value)
    }
}

pub trait KzgPreset:
    'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    type KzgSettings: Debug + Sync + Send;
    type Blob: BlobTrait;

    const BYTES_PER_BLOB: usize;
    const FIELD_ELEMENTS_PER_BLOB: usize;

    fn spec_name() -> KzgPresetId;

    fn load_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self::KzgSettings, Error>;

    fn compute_blob_kzg_proof(
        blob: &Self::Blob,
        kzg_commitment: KzgCommitment,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<KzgProof, Error>;

    fn verify_blob_kzg_proof(
        blob: &Self::Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, Error>;

    fn verify_blob_kzg_proof_batch(
        blobs: &[Self::Blob],
        commitments_bytes: &[Bytes48],
        proofs_bytes: &[Bytes48],
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, Error>;

    fn blob_to_kzg_commitment(
        blob: &Self::Blob,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<KzgCommitment, Error>;

    fn compute_kzg_proof(
        blob: &Self::Blob,
        z: &Bytes32,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<(KzgProof, Bytes32), Error>;

    fn verify_kzg_proof(
        kzg_commitment: KzgCommitment,
        z: &Bytes32,
        y: &Bytes32,
        kzg_proof: KzgProof,
        trusted_setup: &Self::KzgSettings,
    ) -> Result<bool, Error>;
}

macro_rules! implement_kzg_preset {
    ($preset_type:ident, $module_name:ident, $preset_id:ident) => {
        impl KzgPreset for $preset_type {
            type KzgSettings = $module_name::KzgSettings;
            type Blob = $module_name::Blob;

            const BYTES_PER_BLOB: usize = $module_name::BYTES_PER_BLOB;
            const FIELD_ELEMENTS_PER_BLOB: usize = $module_name::FIELD_ELEMENTS_PER_BLOB;

            fn spec_name() -> KzgPresetId {
                KzgPresetId::$preset_id
            }

            fn load_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self::KzgSettings, Error> {
                if trusted_setup.g1_len() != Self::FIELD_ELEMENTS_PER_BLOB {
                    return Err(Error::InconsistentTrustedSetup);
                }
                $module_name::Kzg::load_trusted_setup(
                    &trusted_setup.g1_points(),
                    &trusted_setup.g2_points(),
                )
                .map_err(Into::into)
            }

            fn compute_blob_kzg_proof(
                blob: &Self::Blob,
                kzg_commitment: KzgCommitment,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<KzgProof, Error> {
                $module_name::Kzg::compute_blob_kzg_proof(
                    blob,
                    &kzg_commitment.into(),
                    trusted_setup,
                )
                .map(|proof| KzgProof(proof.to_bytes().into_inner()))
                .map_err(Into::into)
            }

            fn verify_blob_kzg_proof(
                blob: &Self::Blob,
                kzg_commitment: KzgCommitment,
                kzg_proof: KzgProof,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, Error> {
                $module_name::Kzg::verify_blob_kzg_proof(
                    blob,
                    &kzg_commitment.into(),
                    &kzg_proof.into(),
                    trusted_setup,
                )
                .map_err(Into::into)
            }

            fn verify_blob_kzg_proof_batch(
                blobs: &[Self::Blob],
                commitments_bytes: &[Bytes48],
                proofs_bytes: &[Bytes48],
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, Error> {
                $module_name::Kzg::verify_blob_kzg_proof_batch(
                    blobs,
                    commitments_bytes,
                    proofs_bytes,
                    trusted_setup,
                )
                .map_err(Into::into)
            }

            fn blob_to_kzg_commitment(
                blob: &Self::Blob,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<KzgCommitment, Error> {
                $module_name::Kzg::blob_to_kzg_commitment(blob, trusted_setup)
                    .map(|com| KzgCommitment(com.to_bytes().into_inner()))
                    .map_err(Into::into)
            }

            fn compute_kzg_proof(
                blob: &Self::Blob,
                z: &Bytes32,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<(KzgProof, Bytes32), Error> {
                $module_name::Kzg::compute_kzg_proof(blob, z, trusted_setup)
                    .map(|(proof, y)| (KzgProof(proof.to_bytes().into_inner()), y))
                    .map_err(Into::into)
            }

            fn verify_kzg_proof(
                kzg_commitment: KzgCommitment,
                z: &Bytes32,
                y: &Bytes32,
                kzg_proof: KzgProof,
                trusted_setup: &Self::KzgSettings,
            ) -> Result<bool, Error> {
                $module_name::Kzg::verify_kzg_proof(
                    &kzg_commitment.into(),
                    z,
                    y,
                    &kzg_proof.into(),
                    trusted_setup,
                )
                .map_err(Into::into)
            }
        }

        impl BlobTrait for $module_name::Blob {
            fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_bytes(bytes).map_err(Into::into)
            }
        }
    };
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MainnetKzgPreset;
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MinimalKzgPreset;

use c_kzg::kzg_mainnet as mainnet;
use c_kzg::kzg_minimal as minimal;

implement_kzg_preset!(MainnetKzgPreset, mainnet, Mainnet);
implement_kzg_preset!(MinimalKzgPreset, minimal, Minimal);

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
            trusted_setup: P::load_trusted_setup(trusted_setup)?,
        })
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &P::Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        P::compute_blob_kzg_proof(blob, kzg_commitment, &self.trusted_setup)
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &P::Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        P::verify_blob_kzg_proof(blob, kzg_commitment, kzg_proof, &self.trusted_setup)
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
            .map(|comm| Bytes48::from(*comm))
            .collect::<Vec<_>>();

        let proofs_bytes = kzg_proofs
            .iter()
            .map(|proof| Bytes48::from(*proof))
            .collect::<Vec<_>>();

        P::verify_blob_kzg_proof_batch(
            blobs,
            &commitments_bytes,
            &proofs_bytes,
            &self.trusted_setup,
        )
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: &P::Blob) -> Result<KzgCommitment, Error> {
        P::blob_to_kzg_commitment(blob, &self.trusted_setup)
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: &P::Blob,
        z: &Bytes32,
    ) -> Result<(KzgProof, Bytes32), Error> {
        P::compute_kzg_proof(blob, z, &self.trusted_setup)
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KzgCommitment,
        z: &Bytes32,
        y: &Bytes32,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        P::verify_kzg_proof(kzg_commitment, z, y, kzg_proof, &self.trusted_setup)
    }
}
