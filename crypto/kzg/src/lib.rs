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
pub use c_kzg::{Cell, CELLS_PER_EXT_BLOB};
use mockall::automock;

#[derive(Debug)]
pub enum Error {
    /// An error from the underlying kzg library.
    Kzg(c_kzg::Error),
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
}

#[automock]
impl Kzg {
    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    pub fn new_from_trusted_setup(trusted_setup: TrustedSetup) -> Result<Self, Error> {
        Ok(Self {
            trusted_setup: KzgSettings::load_trusted_setup(
                &trusted_setup.g1_points(),
                &trusted_setup.g2_points(),
                0,
            )?,
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
    ) -> Result<
        (
            Box<[Cell; CELLS_PER_EXT_BLOB]>,
            Box<[KzgProof; CELLS_PER_EXT_BLOB]>,
        ),
        Error,
    > {
        let (cells, proofs) = c_kzg::Cell::compute_cells_and_kzg_proofs(blob, &self.trusted_setup)
            .map_err(Into::<Error>::into)?;
        let proofs = Box::new(proofs.map(|proof| KzgProof::from(proof.to_bytes().into_inner())));
        Ok((cells, proofs))
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    ///
    /// Here, `coordinates` correspond to the (row, col) coordinate of the cell in the extended
    /// blob "matrix". In the 1D extension, row corresponds to the blob index, and col corresponds
    /// to the data column index.
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[Cell],
        kzg_proofs: &[Bytes48],
        coordinates: &[(u64, u64)],
        kzg_commitments: &[Bytes48],
    ) -> Result<(), Error> {
        let (rows, columns): (Vec<u64>, Vec<u64>) = coordinates.iter().cloned().unzip();
        if !c_kzg::KzgProof::verify_cell_kzg_proof_batch(
            kzg_commitments,
            &rows,
            &columns,
            cells,
            kzg_proofs,
            &self.trusted_setup,
        )? {
            Err(Error::KzgVerificationFailed)
        } else {
            Ok(())
        }
    }

    pub fn cells_to_blob(&self, cells: &[Cell; c_kzg::CELLS_PER_EXT_BLOB]) -> Result<Blob, Error> {
        Ok(Blob::cells_to_blob(cells)?)
    }

    pub fn recover_all_cells(
        &self,
        cell_ids: &[u64],
        cells: &[Cell],
    ) -> Result<Box<[Cell; c_kzg::CELLS_PER_EXT_BLOB]>, Error> {
        Ok(c_kzg::Cell::recover_all_cells(
            cell_ids,
            cells,
            &self.trusted_setup,
        )?)
    }
}

pub mod mock {
    use crate::{Error, KzgProof};
    use c_kzg::{Blob, Cell, CELLS_PER_EXT_BLOB};

    pub const MOCK_KZG_BYTES_PER_CELL: usize = 2048;

    #[allow(clippy::type_complexity)]
    pub fn compute_cells_and_proofs(
        _blob: &Blob,
    ) -> Result<
        (
            Box<[Cell; CELLS_PER_EXT_BLOB]>,
            Box<[KzgProof; CELLS_PER_EXT_BLOB]>,
        ),
        Error,
    > {
        let empty_cell = Cell::new([0; MOCK_KZG_BYTES_PER_CELL]);
        Ok((
            Box::new([empty_cell; CELLS_PER_EXT_BLOB]),
            Box::new([KzgProof::empty(); CELLS_PER_EXT_BLOB]),
        ))
    }
}

impl TryFrom<TrustedSetup> for Kzg {
    type Error = Error;

    fn try_from(trusted_setup: TrustedSetup) -> Result<Self, Self::Error> {
        Kzg::new_from_trusted_setup(trusted_setup)
    }
}
