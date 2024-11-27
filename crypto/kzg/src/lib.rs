mod kzg_commitment;
mod kzg_proof;
pub mod trusted_setup;

use rust_eth_kzg::{CellIndex, DASContext};
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

pub use rust_eth_kzg::{
    constants::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB},
    Cell, CellIndex as CellID, CellRef, TrustedSetup as PeerDASTrustedSetup,
};

pub type CellsAndKzgProofs = ([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]);

pub type KzgBlobRef<'a> = &'a [u8; BYTES_PER_BLOB];

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

        let context = DASContext::new(&peerdas_trusted_setup, rust_eth_kzg::UsePrecomp::No);

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
            rust_eth_kzg::UsePrecomp::Yes {
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
        // Initialize the trusted setup using default parameters
        //
        // Note: One can also use `from_json` to initialize it from the consensus-specs
        // json string.
        let peerdas_trusted_setup = PeerDASTrustedSetup::from(&trusted_setup);

        // It's not recommended to change the config parameter for precomputation as storage
        // grows exponentially, but the speedup is exponential - after a while the speedup
        // starts to become sublinear.
        let context = DASContext::new(
            &peerdas_trusted_setup,
            rust_eth_kzg::UsePrecomp::Yes {
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
    pub fn compute_cells_and_proofs(
        &self,
        blob: KzgBlobRef<'_>,
    ) -> Result<CellsAndKzgProofs, Error> {
        let (cells, proofs) = self
            .context()
            .compute_cells_and_kzg_proofs(blob)
            .map_err(Error::PeerDASKZG)?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(KzgProof);
        Ok((cells, c_kzg_proof))
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    ///
    /// Here, `coordinates` correspond to the (row, col) coordinate of the cell in the extended
    /// blob "matrix". In the 1D extension, row corresponds to the blob index, and col corresponds
    /// to the data column index.
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[CellRef<'_>],
        kzg_proofs: &[Bytes48],
        columns: Vec<CellIndex>,
        kzg_commitments: &[Bytes48],
    ) -> Result<(), Error> {
        let proofs: Vec<_> = kzg_proofs.iter().map(|proof| proof.as_ref()).collect();
        let commitments: Vec<_> = kzg_commitments
            .iter()
            .map(|commitment| commitment.as_ref())
            .collect();
        let verification_result = self.context().verify_cell_kzg_proof_batch(
            commitments.to_vec(),
            columns,
            cells.to_vec(),
            proofs.to_vec(),
        );

        // Modify the result so it matches roughly what the previous method was doing.
        match verification_result {
            Ok(_) => Ok(()),
            Err(e) if e.invalid_proof() => Err(Error::KzgVerificationFailed),
            Err(e) => Err(Error::PeerDASKZG(e)),
        }
    }

    pub fn recover_cells_and_compute_kzg_proofs(
        &self,
        cell_ids: &[u64],
        cells: &[CellRef<'_>],
    ) -> Result<CellsAndKzgProofs, Error> {
        let (cells, proofs) = self
            .context()
            .recover_cells_and_kzg_proofs(cell_ids.to_vec(), cells.to_vec())
            .map_err(Error::PeerDASKZG)?;

        // Convert the proof type to a c-kzg proof type
        let c_kzg_proof = proofs.map(KzgProof);
        Ok((cells, c_kzg_proof))
    }
}
