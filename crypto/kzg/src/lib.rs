mod kzg_commitment;
mod kzg_proof;
pub mod trusted_setup;

use c_kzg::KzgSettings;
use kzg_types::{
    Blob, Bytes32, Bytes48, CellRef, CellsAndKzgProofs, KzgBlobRef,
    TrustedSetup, *, // Re-export all constants
};
use rand::Rng;
use rust_eth_kzg::{CellIndex, DASContext, UsePrecomp};
use std::fmt::Debug;

// Re-export necessary types/constants from kzg_types for downstream crates
pub use kzg_types::{
    KzgCommitment, KzgProof, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT, VERSIONED_HASH_VERSION_KZG,
};


// Re-export necessary items from c_kzg (excluding types now in kzg_types)
pub use c_kzg::KzgSettings as CKzgSettings;

// Re-export necessary items from rust_eth_kzg (excluding types now in kzg_types)
pub use rust_eth_kzg::{CellIndex as CKzgCellIndex, DASContext as CKzgDASContext};

// Type aliases pointing to kzg_types versions.
pub type CellsAndKzgProofsAlias = CellsAndKzgProofs;
pub type KzgBlobRefAlias<'a> = KzgBlobRef<'a>;


#[derive(Debug)]
pub enum Error {
    /// An error from the underlying kzg library.
    Kzg(c_kzg::Error),
    /// A prover/verifier error from the rust-eth-kzg library.
    PeerDASKZG(rust_eth_kzg::Error),
    /// The kzg verification failed
    KzgVerificationFailed,
    /// Misc indexing error
    InconsistentArrayLength(String),
    /// Error reconstructing data columns.
    ReconstructFailed(String),
    /// Kzg was not initialized with PeerDAS enabled.
    DASContextUninitialized,
}

impl From<c_kzg::Error> for Error {
    fn from(value: c_kzg::Error) -> Self {
        Error::Kzg(value)
    }
}

/// A wrapper over a kzg library that holds the trusted setup parameters.
#[derive(Debug)]
pub struct Kzg {
    trusted_setup: KzgSettings,
    context: DASContext,
}

impl Kzg {
    pub fn new_from_trusted_setup_no_precomp(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);
        let context = DASContext::new(&peerdas_trusted_setup, UsePrecomp::No);

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);
        let context = DASContext::new(
            &peerdas_trusted_setup,
            UsePrecomp::Yes {
                width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
            },
        );

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    pub fn new_from_trusted_setup_das_enabled(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);
        let context = DASContext::new(
            &peerdas_trusted_setup,
            UsePrecomp::Yes {
                width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
            },
        );

        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
            )?,
            context,
        })
    }

    fn context(&self) -> &DASContext {
        &self.context
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        let commitment_bytes: c_kzg::Bytes48 = kzg_commitment.0.into();
        c_kzg::KzgProof::compute_blob_kzg_proof(&(*blob).into(), &commitment_bytes, &self.trusted_setup)
            .map(|proof| kzg_types::KzgProof(*proof.to_bytes().as_ref()))
            .map_err(Into::into)
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<(), Error> {
        let commitment_bytes: c_kzg::Bytes48 = kzg_commitment.0.into();
        let proof_bytes: c_kzg::Bytes48 = kzg_proof.0.into();
        if !c_kzg::KzgProof::verify_blob_kzg_proof(
            &(*blob).into(),
            &commitment_bytes,
            &proof_bytes,
            &self.trusted_setup,
        )? {
            Err(Error::KzgVerificationFailed)
        } else {
            Ok(())
        }
    }

    /// Verify a batch of blob commitment proof triplets.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        kzg_commitments: &[KzgCommitment],
        kzg_proofs: &[KzgProof],
    ) -> Result<(), Error> {
        let commitments_bytes: Vec<c_kzg::Bytes48> = kzg_commitments
            .iter()
            .map(|comm| comm.0.into())
            .collect();

        let proofs_bytes: Vec<c_kzg::Bytes48> = kzg_proofs
            .iter()
            .map(|proof| proof.0.into())
            .collect();

        let blobs_ckzg: Vec<c_kzg::Blob> = blobs.iter().map(|b| (*b).into()).collect();

        if !c_kzg::KzgProof::verify_blob_kzg_proof_batch(
            &blobs_ckzg,
            &commitments_bytes,
            &proofs_bytes,
            &self.trusted_setup,
        )? {
            Err(Error::KzgVerificationFailed)
        } else {
            Ok(())
        }
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: &kzg_types::Blob) -> Result<kzg_types::KzgCommitment, Error> {
        c_kzg::KzgCommitment::blob_to_kzg_commitment(&(*blob).into(), &self.trusted_setup)
            .map(|commitment| kzg_types::KzgCommitment(*commitment.to_bytes().as_ref()))
            .map_err(Into::into)
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: &kzg_types::Blob,
        z: &kzg_types::Bytes32,
    ) -> Result<(kzg_types::KzgProof, kzg_types::Bytes32), Error> {
        c_kzg::KzgProof::compute_kzg_proof(&(*blob).into(), &(*z).into(), &self.trusted_setup)
            .map(|(proof, y)| {
                (
                    kzg_types::KzgProof(*proof.to_bytes().as_ref()),
                    *y.as_ref(),
                )
            })
            .map_err(Into::into)
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KzgCommitment,
        z: &Bytes32,
        y: &Bytes32,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        let commitment_bytes: c_kzg::Bytes48 = kzg_commitment.0.into();
        let proof_bytes: c_kzg::Bytes48 = kzg_proof.0.into();
        c_kzg::KzgProof::verify_kzg_proof(
            &commitment_bytes,
            &(*z).into(),
            &(*y).into(),
            &proof_bytes,
            &self.trusted_setup,
        )
        .map_err(Into::into)
    }

    /// Computes the cells and associated proofs for a given `blob`.
    pub fn compute_cells_and_proofs(
        &self,
        blob: KzgBlobRef<'_>,
    ) -> Result<CellsAndKzgProofs, Error> {
        let (cells, proofs) = self
            .context()
            .compute_cells_and_kzg_proofs(blob)
            .map_err(Error::PeerDASKZG)?;

        let kzg_proofs_array = proofs.map(|p| kzg_types::KzgProof(p));
        Ok((cells, kzg_proofs_array))
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[CellRef<'_>],
        kzg_proofs: &[Bytes48],
        columns: Vec<CellIndex>,
        kzg_commitments: &[Bytes48],
    ) -> Result<(), Error> {
        let commitments_refs: Result<Vec<&[u8; 48]>, _> = kzg_commitments
            .iter()
            .map(|c| c.as_slice().try_into())
            .collect();
        let proofs_refs: Result<Vec<&[u8; 48]>, _> = kzg_proofs
            .iter()
            .map(|p| p.as_slice().try_into())
            .collect();

        let commitments_refs = commitments_refs.map_err(|e| {
            Error::InconsistentArrayLength(format!("Failed to convert commitments: {}", e))
        })?;
        let proofs_refs = proofs_refs.map_err(|e| {
            Error::InconsistentArrayLength(format!("Failed to convert proofs: {}", e))
        })?;

        let verification_result = self.context().verify_cell_kzg_proof_batch(
            commitments_refs,
            columns,
            cells.to_vec(),
            proofs_refs,
        );

        match verification_result {
            Ok(_) => Ok(()),
            Err(e) if e.invalid_proof() => Err(Error::KzgVerificationFailed),
            Err(e) => Err(Error::PeerDASKZG(e)),
        }
    }

    /// Recovers cells and computes proofs.
    pub fn recover_cells_and_compute_kzg_proofs(
        &self,
        cell_ids: &[u64],
        cells: &[CellRef<'_>],
    ) -> Result<CellsAndKzgProofs, Error> {
        let (recovered_cells, recovered_proofs) = self
            .context()
            .recover_cells_and_kzg_proofs(cell_ids.to_vec(), cells.to_vec())
            .map_err(Error::PeerDASKZG)?;

        let kzg_proofs_array = recovered_proofs.map(|p| kzg_types::KzgProof(p));
        Ok((recovered_cells, kzg_proofs_array))
    }

    /// Generates a random blob, KZG commitment, and KZG proof.
    ///
    /// This function is intended for testing purposes.
    pub fn generate_random_blob_commitment_proof<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Blob, KzgCommitment, KzgProof), Error> {
        let mut blob_bytes = vec![0u8; BYTES_PER_BLOB];
        rng.fill_bytes(&mut blob_bytes);
        for byte in blob_bytes.iter_mut().step_by(BYTES_PER_FIELD_ELEMENT) {
            *byte = 0;
            }

        // Convert the Vec<u8> to a fixed-size array kzg_types::Blob
        let kzg_blob: Blob = blob_bytes
            .try_into()
            .map_err(|_| Error::InconsistentArrayLength("Failed to convert Vec<u8> to Blob".to_string()))?;

        let commitment = self.blob_to_kzg_commitment(&kzg_blob)?;

        let proof = self.compute_blob_kzg_proof(&kzg_blob, commitment)?;

        Ok((kzg_blob, commitment, proof))
    }

}
