mod kzg_commitment;
mod kzg_proof;
pub mod trusted_setup;

use rust_eth_kzg::{CellIndex, DASContext};
use std::collections::HashMap;
use std::fmt::Debug;

pub use crate::{
    kzg_commitment::{KzgCommitment, VERSIONED_HASH_VERSION_KZG},
    kzg_proof::KzgProof,
    trusted_setup::TrustedSetup,
};

pub use rust_eth_kzg::constants::{
    BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, FIELD_ELEMENTS_PER_BLOB,
};

pub const BYTES_PER_PROOF: usize = 48;

use crate::trusted_setup::load_trusted_setup;
use rayon::prelude::*;
pub use rust_eth_kzg::{
    constants::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB},
    Cell, CellIndex as CellID, CellRef, TrustedSetup as PeerDASTrustedSetup,
};
use tracing::{instrument, Span};

// Note: Both `NUMBER_OF_COLUMNS` and `CELLS_PER_EXT_BLOB` are preset values - however this
// is a constant in the KZG library - be aware that overriding `NUMBER_OF_COLUMNS` will break KZG
// operations.
pub type CellsAndKzgProofs = ([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]);

pub type KzgBlobRef<'a> = &'a [u8; BYTES_PER_BLOB];

type Bytes32 = [u8; 32];
type Bytes48 = [u8; 48];

#[derive(Debug)]
pub enum Error {
    /// An error from initialising the trusted setup.
    TrustedSetupError(String),
    /// An error from the rust-eth-kzg library.
    Kzg(rust_eth_kzg::Error),
    /// The kzg verification failed
    KzgVerificationFailed,
    /// Misc indexing error
    InconsistentArrayLength(String),
    /// Error reconstructing data columns.
    ReconstructFailed(String),
    /// Kzg was not initialized with PeerDAS enabled.
    DASContextUninitialized,
}

impl From<rust_eth_kzg::Error> for Error {
    fn from(value: rust_eth_kzg::Error) -> Self {
        Error::Kzg(value)
    }
}

/// A wrapper over the rust-eth-kzg library that holds the trusted setup parameters.
#[derive(Debug)]
pub struct Kzg {
    context: DASContext,
}

impl Kzg {
    pub fn new_from_trusted_setup_no_precomp(trusted_setup: &[u8]) -> Result<Self, Error> {
        let rkzg_trusted_setup = load_trusted_setup(trusted_setup)?;
        let context = DASContext::new(&rkzg_trusted_setup, rust_eth_kzg::UsePrecomp::No);

        Ok(Self { context })
    }

    /// Load the kzg trusted setup parameters from a vec of G1 and G2 points.
    pub fn new_from_trusted_setup(trusted_setup: &[u8]) -> Result<Self, Error> {
        let rkzg_trusted_setup = load_trusted_setup(trusted_setup)?;

        // It's not recommended to change the config parameter for precomputation as storage
        // grows exponentially, but the speedup is exponential - after a while the speedup
        // starts to become sublinear.
        let context = DASContext::new(
            &rkzg_trusted_setup,
            rust_eth_kzg::UsePrecomp::Yes {
                width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
            },
        );

        Ok(Self { context })
    }

    fn context(&self) -> &DASContext {
        &self.context
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: KzgBlobRef<'_>,
        kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        let proof = self
            .context()
            .compute_blob_kzg_proof(blob, &kzg_commitment.0)
            .map_err(Error::Kzg)?;
        Ok(KzgProof(proof))
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: KzgBlobRef<'_>,
        kzg_commitment: KzgCommitment,
        kzg_proof: KzgProof,
    ) -> Result<(), Error> {
        if cfg!(feature = "fake_crypto") {
            return Ok(());
        }
        self.context()
            .verify_blob_kzg_proof(blob, &kzg_commitment.0, &kzg_proof.0)
            .map_err(|e| {
                if e.is_proof_invalid() {
                    Error::KzgVerificationFailed
                } else {
                    Error::Kzg(e)
                }
            })
    }

    /// Verify a batch of blob commitment proof triplets.
    ///
    /// Note: This method is slightly faster than calling `Self::verify_blob_kzg_proof` in a loop sequentially.
    /// TODO(pawan): test performance against a parallelized rayon impl.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[KzgBlobRef<'_>],
        kzg_commitments: &[KzgCommitment],
        kzg_proofs: &[KzgProof],
    ) -> Result<(), Error> {
        if cfg!(feature = "fake_crypto") {
            return Ok(());
        }
        let blob_refs: Vec<&[u8; BYTES_PER_BLOB]> = blobs.to_vec();
        let commitment_refs: Vec<&[u8; 48]> = kzg_commitments.iter().map(|c| &c.0).collect();
        let proof_refs: Vec<&[u8; 48]> = kzg_proofs.iter().map(|p| &p.0).collect();

        self.context()
            .verify_blob_kzg_proof_batch(blob_refs, commitment_refs, proof_refs)
            .map_err(|e| {
                if e.is_proof_invalid() {
                    Error::KzgVerificationFailed
                } else {
                    Error::Kzg(e)
                }
            })
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, blob: KzgBlobRef<'_>) -> Result<KzgCommitment, Error> {
        let commitment = self
            .context()
            .blob_to_kzg_commitment(blob)
            .map_err(Error::Kzg)?;
        Ok(KzgCommitment(commitment))
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        blob: KzgBlobRef<'_>,
        z: &Bytes32,
    ) -> Result<(KzgProof, Bytes32), Error> {
        let (proof, y) = self
            .context()
            .compute_kzg_proof(blob, *z)
            .map_err(Error::Kzg)?;
        Ok((KzgProof(proof), y))
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KzgCommitment,
        z: &Bytes32,
        y: &Bytes32,
        kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        if cfg!(feature = "fake_crypto") {
            return Ok(true);
        }
        match self
            .context()
            .verify_kzg_proof(&kzg_commitment.0, *z, *y, &kzg_proof.0)
        {
            Ok(()) => Ok(true),
            Err(e) if e.is_proof_invalid() => Ok(false),
            Err(e) => Err(Error::Kzg(e)),
        }
    }

    /// Computes the cells and associated proofs for a given `blob`.
    pub fn compute_cells_and_proofs(
        &self,
        blob: KzgBlobRef<'_>,
    ) -> Result<CellsAndKzgProofs, Error> {
        let (cells, proofs) = self
            .context()
            .compute_cells_and_kzg_proofs(blob)
            .map_err(Error::Kzg)?;

        let kzg_proofs = proofs.map(KzgProof);
        Ok((cells, kzg_proofs))
    }

    /// Computes the cells for a given `blob`.
    pub fn compute_cells(&self, blob: KzgBlobRef<'_>) -> Result<[Cell; CELLS_PER_EXT_BLOB], Error> {
        self.context().compute_cells(blob).map_err(Error::Kzg)
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    #[instrument(skip_all, level = "debug", fields(cells = cells.len()))]
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[CellRef<'_>],
        kzg_proofs: &[Bytes48],
        indices: Vec<CellIndex>,
        kzg_commitments: &[Bytes48],
    ) -> Result<(), (Option<u64>, Error)> {
        if cfg!(feature = "fake_crypto") {
            return Ok(());
        }
        let mut column_groups: HashMap<u64, Vec<(CellRef, Bytes48, Bytes48)>> = HashMap::new();

        let expected_len = cells.len();

        // This check is already made in `validate_data_columns`. However we add it here so that ef consensus spec tests pass
        // and to avoid any potential footguns in the future. Note that by catching the error here and not in `validate_data_columns`
        // the error becomes non-attributable.
        if kzg_proofs.len() != expected_len
            || indices.len() != expected_len
            || kzg_commitments.len() != expected_len
        {
            return Err((
                None,
                Error::InconsistentArrayLength("Invalid data column".to_string()),
            ));
        }

        for (((cell, proof), &index), commitment) in cells
            .iter()
            .zip(kzg_proofs.iter())
            .zip(indices.iter())
            .zip(kzg_commitments.iter())
        {
            column_groups
                .entry(index)
                .or_default()
                .push((cell, *proof, *commitment));
        }

        let span = Span::current();
        column_groups
            .into_par_iter()
            .map(|(column_index, column_data)| {
                let mut cells = Vec::new();
                let mut proofs = Vec::new();
                let mut commitments = Vec::new();

                for (cell, proof, commitment) in &column_data {
                    cells.push(*cell);
                    proofs.push(proof);
                    commitments.push(commitment);
                }

                // Create per-chunk tracing span for visualizing parallel processing.
                // This is safe from span explosion as we have at most 128 chunks,
                // i.e. the number of column indices.
                let _span = tracing::debug_span!(
                    parent: span.clone(),
                    "verify_cell_proof_chunk",
                    cells = cells.len(),
                    column_index,
                    verification_result = tracing::field::Empty,
                )
                .entered();

                let verification_result = self.context().verify_cell_kzg_proof_batch(
                    commitments,
                    &vec![column_index; cells.len()], // All column_data here is from the same index
                    cells,
                    proofs,
                );

                match verification_result {
                    Ok(_) => Ok(()),
                    Err(e) if e.is_proof_invalid() => {
                        Err((Some(column_index), Error::KzgVerificationFailed))
                    }
                    Err(e) => Err((Some(column_index), Error::Kzg(e))),
                }
            })
            .collect::<Result<Vec<()>, (Option<u64>, Error)>>()?;

        Ok(())
    }

    pub fn recover_cells_and_compute_kzg_proofs(
        &self,
        cell_ids: &[u64],
        cells: &[CellRef<'_>],
    ) -> Result<CellsAndKzgProofs, Error> {
        let (cells, proofs) = self
            .context()
            .recover_cells_and_kzg_proofs(cell_ids.to_vec(), cells.to_vec())
            .map_err(Error::Kzg)?;

        let kzg_proofs = proofs.map(KzgProof);
        Ok((cells, kzg_proofs))
    }
}
