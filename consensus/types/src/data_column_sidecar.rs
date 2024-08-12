use crate::beacon_block_body::{KzgCommitments, BLOB_KZG_COMMITMENTS_INDEX};
use crate::test_utils::TestRandom;
use crate::{
    BeaconBlockHeader, ChainSpec, EthSpec, Hash256, KzgProofs, SignedBeaconBlock,
    SignedBeaconBlockHeader, Slot,
};
use crate::{BeaconStateError, BlobsList};
use bls::Signature;
use derivative::Derivative;
use kzg::Kzg;
use kzg::{Blob as KzgBlob, Cell as KzgCell, Error as KzgError};
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
use rayon::prelude::*;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
use std::hash::Hash;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type ColumnIndex = u64;
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::BytesPerCell>;
pub type DataColumn<E> = VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Container of the data that identifies an individual data column.
#[derive(
    Serialize, Deserialize, Encode, Decode, TreeHash, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct DataColumnIdentifier {
    pub block_root: Hash256,
    pub index: ColumnIndex,
}

pub type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct DataColumnSidecar<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: ColumnIndex,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<E>,
    /// All of the KZG commitments and proofs associated with the block, used for verifying sample cells.
    pub kzg_commitments: KzgCommitments<E>,
    pub kzg_proofs: KzgProofs<E>,
    pub signed_block_header: SignedBeaconBlockHeader,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
}

impl<E: EthSpec> DataColumnSidecar<E> {
    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }

    pub fn block_parent_root(&self) -> Hash256 {
        self.signed_block_header.message.parent_root
    }

    pub fn block_proposer_index(&self) -> u64 {
        self.signed_block_header.message.proposer_index
    }

    /// Verifies the kzg commitment inclusion merkle proof.
    pub fn verify_inclusion_proof(&self) -> bool {
        let blob_kzg_commitments_root = self.kzg_commitments.tree_hash_root();

        verify_merkle_proof(
            blob_kzg_commitments_root,
            &self.kzg_commitments_inclusion_proof,
            E::kzg_commitments_inclusion_proof_depth(),
            BLOB_KZG_COMMITMENTS_INDEX,
            self.signed_block_header.message.body_root,
        )
    }

    pub fn build_sidecars(
        blobs: &BlobsList<E>,
        block: &SignedBeaconBlock<E>,
        kzg: &Kzg,
        spec: &ChainSpec,
    ) -> Result<DataColumnSidecarList<E>, DataColumnSidecarError> {
        let number_of_columns = spec.number_of_columns;
        if blobs.is_empty() {
            return Ok(vec![]);
        }
        let kzg_commitments = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_err| DataColumnSidecarError::PreDeneb)?;
        let kzg_commitments_inclusion_proof =
            block.message().body().kzg_commitments_merkle_proof()?;
        let signed_block_header = block.signed_block_header();

        let mut columns = vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];
        let mut column_kzg_proofs =
            vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];

        // NOTE: assumes blob sidecars are ordered by index
        let blob_cells_and_proofs_vec = blobs
            .into_par_iter()
            .map(|blob| {
                let blob = KzgBlob::from_bytes(blob).map_err(KzgError::from)?;
                kzg.compute_cells_and_proofs(&blob)
            })
            .collect::<Result<Vec<_>, KzgError>>()?;

        for (blob_cells, blob_cell_proofs) in blob_cells_and_proofs_vec {
            // we iterate over each column, and we construct the column from "top to bottom",
            // pushing on the cell and the corresponding proof at each column index. we do this for
            // each blob (i.e. the outer loop).
            for col in 0..number_of_columns {
                let cell =
                    blob_cells
                        .get(col)
                        .ok_or(DataColumnSidecarError::InconsistentArrayLength(format!(
                            "Missing blob cell at index {col}"
                        )))?;
                let cell: Vec<u8> = cell.into_inner().into_iter().collect();
                let cell = Cell::<E>::from(cell);

                let proof = blob_cell_proofs.get(col).ok_or(
                    DataColumnSidecarError::InconsistentArrayLength(format!(
                        "Missing blob cell KZG proof at index {col}"
                    )),
                )?;

                let column =
                    columns
                        .get_mut(col)
                        .ok_or(DataColumnSidecarError::InconsistentArrayLength(format!(
                            "Missing data column at index {col}"
                        )))?;
                let column_proofs = column_kzg_proofs.get_mut(col).ok_or(
                    DataColumnSidecarError::InconsistentArrayLength(format!(
                        "Missing data column proofs at index {col}"
                    )),
                )?;

                column.push(cell);
                column_proofs.push(*proof);
            }
        }

        let sidecars: Vec<Arc<DataColumnSidecar<E>>> = columns
            .into_iter()
            .zip(column_kzg_proofs)
            .enumerate()
            .map(|(index, (col, proofs))| {
                Arc::new(DataColumnSidecar {
                    index: index as u64,
                    column: DataColumn::<E>::from(col),
                    kzg_commitments: kzg_commitments.clone(),
                    kzg_proofs: KzgProofs::<E>::from(proofs),
                    signed_block_header: signed_block_header.clone(),
                    kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                })
            })
            .collect();

        Ok(sidecars)
    }

    pub fn reconstruct(
        kzg: &Kzg,
        data_columns: &[Arc<Self>],
        spec: &ChainSpec,
    ) -> Result<Vec<Arc<Self>>, KzgError> {
        let number_of_columns = spec.number_of_columns;
        let mut columns = vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];
        let mut column_kzg_proofs =
            vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];

        let first_data_column = data_columns
            .first()
            .ok_or(KzgError::InconsistentArrayLength(
                "data_columns should have at least one element".to_string(),
            ))?;
        let num_of_blobs = first_data_column.kzg_commitments.len();

        let blob_cells_and_proofs_vec = (0..num_of_blobs)
            .into_par_iter()
            .map(|row_index| {
                let mut cells: Vec<KzgCell> = vec![];
                let mut cell_ids: Vec<u64> = vec![];
                for data_column in data_columns {
                    let cell = data_column.column.get(row_index).ok_or(
                        KzgError::InconsistentArrayLength(format!(
                            "Missing data column at index {row_index}"
                        )),
                    )?;

                    cells.push(ssz_cell_to_crypto_cell::<E>(cell)?);
                    cell_ids.push(data_column.index);
                }
                // recover_all_cells does not expect sorted
                let all_cells = kzg.recover_all_cells(&cell_ids, &cells)?;
                let blob = kzg.cells_to_blob(&all_cells)?;

                // Note: This function computes all cells and proofs. According to Justin this is okay,
                // computing a partial set may be more expensive and requires code paths that don't exist.
                // Computing the blobs cells is technically unnecessary but very cheap. It's done here again
                // for simplicity.
                kzg.compute_cells_and_proofs(&blob)
            })
            .collect::<Result<Vec<_>, KzgError>>()?;

        for (blob_cells, blob_cell_proofs) in blob_cells_and_proofs_vec {
            // we iterate over each column, and we construct the column from "top to bottom",
            // pushing on the cell and the corresponding proof at each column index. we do this for
            // each blob (i.e. the outer loop).
            for col in 0..number_of_columns {
                let cell = blob_cells
                    .get(col)
                    .ok_or(KzgError::InconsistentArrayLength(format!(
                        "Missing blob cell at index {col}"
                    )))?;
                let cell: Vec<u8> = cell.into_inner().into_iter().collect();
                let cell = Cell::<E>::from(cell);

                let proof = blob_cell_proofs
                    .get(col)
                    .ok_or(KzgError::InconsistentArrayLength(format!(
                        "Missing blob cell KZG proof at index {col}"
                    )))?;

                let column = columns
                    .get_mut(col)
                    .ok_or(KzgError::InconsistentArrayLength(format!(
                        "Missing data column at index {col}"
                    )))?;
                let column_proofs =
                    column_kzg_proofs
                        .get_mut(col)
                        .ok_or(KzgError::InconsistentArrayLength(format!(
                            "Missing data column proofs at index {col}"
                        )))?;

                column.push(cell);
                column_proofs.push(*proof);
            }
        }

        // Clone sidecar elements from existing data column, no need to re-compute
        let kzg_commitments = &first_data_column.kzg_commitments;
        let signed_block_header = &first_data_column.signed_block_header;
        let kzg_commitments_inclusion_proof = &first_data_column.kzg_commitments_inclusion_proof;

        let sidecars: Vec<Arc<DataColumnSidecar<E>>> = columns
            .into_iter()
            .zip(column_kzg_proofs)
            .enumerate()
            .map(|(index, (col, proofs))| {
                Arc::new(DataColumnSidecar {
                    index: index as u64,
                    column: DataColumn::<E>::from(col),
                    kzg_commitments: kzg_commitments.clone(),
                    kzg_proofs: KzgProofs::<E>::from(proofs),
                    signed_block_header: signed_block_header.clone(),
                    kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                })
            })
            .collect();
        Ok(sidecars)
    }

    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
            kzg_commitments: VariableList::new(vec![KzgCommitment::empty_for_testing()]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size() -> usize {
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default(); E::MaxBlobsPerBlock::to_usize()])
                .unwrap(),
            kzg_commitments: VariableList::new(vec![
                KzgCommitment::empty_for_testing();
                E::MaxBlobsPerBlock::to_usize()
            ])
            .unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); E::MaxBlobsPerBlock::to_usize()])
                .unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn empty() -> Self {
        Self {
            index: 0,
            column: DataColumn::<E>::default(),
            kzg_commitments: VariableList::default(),
            kzg_proofs: VariableList::default(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
    }

    pub fn id(&self) -> DataColumnIdentifier {
        DataColumnIdentifier {
            block_root: self.block_root(),
            index: self.index,
        }
    }
}

#[derive(Debug)]
pub enum DataColumnSidecarError {
    ArithError(ArithError),
    BeaconStateError(BeaconStateError),
    DataColumnIndexOutOfBounds,
    KzgCommitmentInclusionProofOutOfBounds,
    KzgError(KzgError),
    MissingBlobSidecars,
    PreDeneb,
    SszError(SszError),
    InconsistentArrayLength(String),
}

impl From<ArithError> for DataColumnSidecarError {
    fn from(e: ArithError) -> Self {
        Self::ArithError(e)
    }
}

impl From<BeaconStateError> for DataColumnSidecarError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconStateError(e)
    }
}

impl From<KzgError> for DataColumnSidecarError {
    fn from(e: KzgError) -> Self {
        Self::KzgError(e)
    }
}

impl From<SszError> for DataColumnSidecarError {
    fn from(e: SszError) -> Self {
        Self::SszError(e)
    }
}

/// Converts a cell ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_cell_to_crypto_cell<E: EthSpec>(cell: &Cell<E>) -> Result<KzgCell, KzgError> {
    KzgCell::from_bytes(cell.as_ref()).map_err(Into::into)
}
