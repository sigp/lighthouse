mod kzg_commitment;
mod kzg_proof;
mod trusted_setup;

use std::fmt::Debug;

pub use crate::{
    kzg_commitment::{KzgCommitment, VERSIONED_HASH_VERSION_KZG},
    kzg_proof::KzgProof,
    trusted_setup::TrustedSetup,
};
pub use c_kzg::{
    Blob, Bytes32, Bytes48, KzgSettings, BYTES_PER_BLOB, BYTES_PER_COMMITMENT,
    BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB,
};
use mockall::automock;

pub use eip7594::{
    constants::BYTES_PER_CELL, constants::CELLS_PER_EXT_BLOB, verifier::VerifierError,
    Bytes48Ref as PeerDASBytes48, Cell, CellID, CellRef, PeerDASContext,
};

#[derive(Debug)]
pub enum Error {
    /// An error from the underlying kzg library.
    Kzg(c_kzg::Error),
    /// A prover error from the PeerdasKZG library
    ProverKZG(eip7594::prover::ProverError),
    /// A verifier error from the PeerdasKZG library
    VerifierKZG(eip7594::verifier::VerifierError),
    /// The kzg verification failed
    KzgVerificationFailed,
    /// Misc indexing error
    InconsistentArrayLength(String),
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
    context: PeerDASContext,
}

#[automock]
impl Kzg {
    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
                // Enable precomputed table for 8 bits, with 96MB of memory overhead per process
                // Ref: https://notes.ethereum.org/@jtraglia/windowed_multiplications
                8,
            )?,
            context: PeerDASContext::default(),
        })
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        c_kzg::KzgProof::compute_blob_kzg_proof(blob, &kzg_commitment.into(), &self.trusted_setup)
            .map(|proof| KzgProof(proof.to_bytes().into_inner()))
            .map_err(Into::into)
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<(), Error> {
        if !c_kzg::KzgProof::verify_blob_kzg_proof(
            blob,
            &kzg_commitment.into(),
            &kzg_proof.into(),
            &self.trusted_setup,
        )? {
            Err(Error::KzgVerificationFailed)
        } else {
            Ok(())
        }
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
    ) -> Result<(), Error> {
        let commitments_bytes = kzg_commitments
            .iter()
            .map(|comm| Bytes48::from(*comm))
            .collect::<Vec<_>>();

        let proofs_bytes = kzg_proofs
            .iter()
            .map(|proof| Bytes48::from(*proof))
            .collect::<Vec<_>>();

        if !c_kzg::KzgProof::verify_blob_kzg_proof_batch(
            blobs,
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
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Result<KzgCommitment, Error> {
        c_kzg::KzgCommitment::blob_to_kzg_commitment(blob, &self.trusted_setup)
            .map(|commitment| KzgCommitment(commitment.to_bytes().into_inner()))
            .map_err(Into::into)
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: &Blob,
        z: &Bytes32,
    ) -> Result<(KzgProof, Bytes32), Error> {
        c_kzg::KzgProof::compute_kzg_proof(blob, z, &self.trusted_setup)
            .map(|(proof, y)| (KzgProof(proof.to_bytes().into_inner()), y))
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
        c_kzg::KzgProof::verify_kzg_proof(
            &kzg_commitment.into(),
            z,
            y,
            &kzg_proof.into(),
            &self.trusted_setup,
        )
        .map_err(Into::into)
    }

    /// Computes the cells and associated proofs for a given `blob` at index `index`.
    #[allow(clippy::type_complexity)]
    pub fn compute_cells_and_proofs(
        &self,
        blob: &Blob,
    ) -> Result<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]), Error> {
        let blob_bytes: &[u8; BYTES_PER_BLOB] = blob
            .as_ref()
            .try_into()
            .expect("Expected blob to have size {BYTES_PER_BLOB}");

        let (cells, proofs) = self
            .context
            .prover_ctx()
            .compute_cells_and_kzg_proofs(blob_bytes)
            .map_err(Error::ProverKZG)?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(|proof| KzgProof(proof));
        Ok((cells, c_kzg_proof))
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    ///
    /// Here, `coordinates` correspond to the (row, col) coordinate of the cell in the extended
    /// blob "matrix". In the 1D extension, row corresponds to the blob index, and col corresponds
    /// to the data column index.
    pub fn verify_cell_proof_batch<'a>(
        &self,
        cells: &[CellRef<'a>],
        kzg_proofs: &[Bytes48],
        coordinates: &[(u64, u64)],
        kzg_commitments: &[Bytes48],
    ) -> Result<(), Error> {
        let (rows, columns): (Vec<u64>, Vec<u64>) = coordinates.iter().cloned().unzip();
        // The result of this is either an Ok indicating the proof passed, or an Err indicating
        // the proof failed or something else went wrong.

        let proofs: Vec<PeerDASBytes48> = kzg_proofs
            .iter()
            .map(|proof| proof.as_ref().try_into().unwrap())
            .collect();
        let commitments: Vec<PeerDASBytes48> = kzg_commitments
            .iter()
            .map(|commitment| commitment.as_ref().try_into().unwrap())
            .collect();
        let verification_result = self.context.verifier_ctx().verify_cell_kzg_proof_batch(
            commitments.to_vec(),
            rows,
            columns,
            cells.to_vec(),
            proofs.to_vec(),
        );

        // Modify the result so it matches roughly what the previous method was doing.
        match verification_result {
            Ok(_) => Ok(()),
            Err(VerifierError::InvalidProof) => Err(Error::KzgVerificationFailed),
            Err(e) => Err(Error::VerifierKZG(e)),
        }
    }

    pub fn recover_cells_and_compute_kzg_proofs<'a>(
        &self,
        cell_ids: &[u64],
        cells: &[CellRef<'a>],
    ) -> Result<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]), Error> {
        let (cells, proofs) = self
            .context
            .prover_ctx()
            .recover_cells_and_proofs(cell_ids.to_vec(), cells.to_vec(), vec![])
            .map_err(Error::ProverKZG)?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(|proof| KzgProof(proof));
        Ok((cells, c_kzg_proof))
    }
}

pub mod mock {
    use crate::{Blob, Cell, BYTES_PER_CELL, CELLS_PER_EXT_BLOB};
    use crate::{Error, KzgProof};

    #[allow(clippy::type_complexity)]
    pub fn compute_cells_and_proofs(
        _blob: &Blob,
    ) -> Result<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]), Error> {
        let empty_cells = vec![Cell::new([0; BYTES_PER_CELL]); CELLS_PER_EXT_BLOB]
            .try_into()
            .expect("expected {CELLS_PER_EXT_BLOB} number of items");
        Ok((empty_cells, [KzgProof::empty(); CELLS_PER_EXT_BLOB]))
    }
}

impl TryFrom<TrustedSetup> for Kzg {
    type Error = Error;

    fn try_from(trusted_setup: TrustedSetup) -> Result<Self, Self::Error> {
        Kzg::new_from_trusted_setup(trusted_setup)
    }
}
