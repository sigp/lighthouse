use crate::beacon_block_body::KzgCommitments;
use crate::data::das_column::{CellWithMetadata, DasColumn};
use crate::data_column_sidecar::{Cell, DataColumn};
use crate::test_utils::TestRandom;
use crate::{AbstractExecPayload, ColumnIndex, DataColumnSidecar};
use crate::{EthSpec, ForkName, Hash256, SignedBeaconBlock, SignedBeaconBlockHeader, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use kzg::KzgProof;
use serde::{Deserialize, Serialize};
use ssz::{BitList, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::borrow::Cow;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type CellBitmap<E> = BitList<<E as EthSpec>::MaxBlobCommitmentsPerBlock>;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom, Educe)]
#[serde(bound = "E: EthSpec")]
#[educe(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[context_deserialize(ForkName)]
pub struct PartialDataColumnSidecar<E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<E>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            cells_present_bitmap: BitList::with_capacity(1).unwrap(),
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn size(present_blobs: usize, block_blobs: usize) -> usize {
        // min size is one cell
        Self {
            cells_present_bitmap: BitList::with_capacity(block_blobs).unwrap(),
            column: VariableList::new(vec![Cell::<E>::default(); present_blobs]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); present_blobs]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            cells_present_bitmap: BitList::with_capacity(max_blobs_per_block).unwrap(),
            column: VariableList::new(vec![Cell::<E>::default(); max_blobs_per_block]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn is_complete(&self) -> bool {
        self.cells_present_bitmap.iter().all(|bit| bit)
    }

    pub fn with_missing_cells(&self, bitmap: &CellBitmap<E>) -> Option<Self> {
        if self.cells_present_bitmap.len() != bitmap.len() {
            return None;
        }
        self.clone_filter(|idx| !bitmap.get(idx).expect("Bounds checked above"))
    }

    /// Creates a new partial data column sidecar containing only the blob indices for which the
    /// passed closure returns `true` and were present in `self`. Will return `None` if there is no
    /// overlap.
    pub fn clone_filter<F>(&self, filter: F) -> Option<Self>
    where
        F: Fn(usize) -> bool,
    {
        let mut new_bitmap = self.cells_present_bitmap.clone();
        let mut new_column = VariableList::default();
        let mut new_proofs = VariableList::default();
        let mut column_idx = 0;

        for (blob_idx, present) in self.cells_present_bitmap.iter().enumerate() {
            if present {
                if filter(blob_idx) {
                    // Keep this cell
                    let cell = self.column.get(column_idx)?;
                    new_column
                        .push(cell.clone())
                        .expect("Has same capacity as existing column");
                    let proof = self.kzg_proofs.get(column_idx)?;
                    new_proofs
                        .push(*proof)
                        .expect("Has same capacity as existing column");
                } else {
                    // Mark as not present
                    new_bitmap
                        .set(blob_idx, false)
                        .expect("Within bounds due to clone above");
                }
                column_idx = column_idx
                    .checked_add(1)
                    .expect("Will not have more cells than 2^64 - 1");
            }
        }

        if new_column.is_empty() {
            return None;
        }

        Some(Self {
            cells_present_bitmap: new_bitmap,
            column: new_column,
            kzg_proofs: new_proofs,
        })
    }

    pub fn merge(&self, other: &Self) -> Option<Self> {
        let new_bitmap = self.cells_present_bitmap.union(&other.cells_present_bitmap);
        let mut new_column = VariableList::default();
        let mut new_proofs = VariableList::default();
        let mut self_cell_idx = 0usize;
        let mut other_cell_idx = 0usize;

        for presence_bits in self
            .cells_present_bitmap
            .iter()
            .zip(other.cells_present_bitmap.iter())
        {
            match presence_bits {
                (false, false) => {}
                (true, other) => {
                    new_column
                        .push(self.column.get(self_cell_idx)?.clone())
                        .expect("Has same capacity");
                    new_proofs
                        .push(*self.kzg_proofs.get(self_cell_idx)?)
                        .expect("Has same capacity");
                    self_cell_idx = self_cell_idx
                        .checked_add(1)
                        .expect("Will not have more cells than 2^64 - 1");
                    if other {
                        other_cell_idx = other_cell_idx
                            .checked_add(1)
                            .expect("Will not have more cells than 2^64 - 1");
                    }
                }
                (false, true) => {
                    new_column
                        .push(other.column.get(other_cell_idx)?.clone())
                        .expect("Has same capacity");
                    new_proofs
                        .push(*other.kzg_proofs.get(other_cell_idx)?)
                        .expect("Has same capacity");
                    other_cell_idx = other_cell_idx
                        .checked_add(1)
                        .expect("Will not have more cells than 2^64 - 1");
                }
            }
        }

        Some(Self {
            cells_present_bitmap: new_bitmap,
            column: new_column,
            kzg_proofs: new_proofs,
        })
    }
}

// TODO(dknopik): More specific error cases - e.g. internal inconsistency
pub struct MissingCellError;

impl<E: EthSpec> From<DataColumnSidecar<E>> for PartialDataColumnSidecar<E> {
    fn from(value: DataColumnSidecar<E>) -> Self {
        // Create a bitmap with all cells marked as present
        let mut cells_present_bitmap = BitList::with_capacity(value.column.len())
            .expect("Bitmap and cell list are both bounded by `MaxBlobCommitmentsPerBlock`");
        for idx in 0..value.column.len() {
            cells_present_bitmap.set(idx, true).expect(
                "Bitmap was created with column length, so we should be able to push a value",
            );
        }

        Self {
            cells_present_bitmap,
            column: value.column,
            kzg_proofs: value.kzg_proofs,
        }
    }
}

// TODO(dknopik): Name?
#[derive(Debug, Clone, PartialEq)]
pub struct DanglingPartialDataColumn<E: EthSpec> {
    pub block_root: Hash256,
    pub index: ColumnIndex,
    pub sidecar: PartialDataColumnSidecar<E>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiablePartialDataColumn<E: EthSpec> {
    pub column: Arc<DanglingPartialDataColumn<E>>,
    pub kzg_commitments: KzgCommitments<E>,
    pub slot: Slot,
}

// TODO(dknopik): Is there an existing approriate error type?
#[derive(Debug)]
pub enum PartialDataColumnMatchingError {
    MismatchingBlock,
    InvalidForkBlock,
}

impl<E: EthSpec> VerifiablePartialDataColumn<E> {
    pub fn from_dangling_and_block<P: AbstractExecPayload<E>>(
        column: Arc<DanglingPartialDataColumn<E>>,
        block: &SignedBeaconBlock<E, P>,
    ) -> Result<Self, PartialDataColumnMatchingError> {
        if column.block_root != block.canonical_root() {
            return Err(PartialDataColumnMatchingError::MismatchingBlock);
        }

        let kzg_commitments = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_| PartialDataColumnMatchingError::InvalidForkBlock)?
            .clone();

        Ok(VerifiablePartialDataColumn {
            column,
            kzg_commitments,
            slot: block.slot(),
        })
    }

    pub fn clone_filter<F>(&self, filter: F) -> Option<Self>
    where
        F: Fn(usize) -> bool,
    {
        Some(VerifiablePartialDataColumn {
            column: Arc::new(DanglingPartialDataColumn {
                sidecar: self.column.sidecar.clone_filter(filter)?,
                block_root: self.column.block_root,
                index: self.column.index,
            }),
            kzg_commitments: self.kzg_commitments.clone(),
            slot: self.slot,
        })
    }
}

impl<E: EthSpec> DasColumn<E> for VerifiablePartialDataColumn<E> {
    fn slot(&self) -> Slot {
        self.slot
    }

    fn index(&self) -> ColumnIndex {
        self.column.index
    }

    fn cell_count_total(&self) -> usize {
        self.column.sidecar.cells_present_bitmap.len()
    }

    fn cells_present(&self) -> impl Iterator<Item = usize> {
        self.column
            .sidecar
            .cells_present_bitmap
            .iter()
            .enumerate()
            .filter_map(|(idx, bit)| bit.then_some(idx))
    }

    fn column(&self) -> &DataColumn<E> {
        &self.column.sidecar.column
    }

    fn kzg_proofs(&self) -> &VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock> {
        &self.column.sidecar.kzg_proofs
    }

    fn kzg_commitments(&self) -> &KzgCommitments<E> {
        &self.kzg_commitments
    }

    fn block_root(&self) -> Hash256 {
        self.column.block_root.tree_hash_root()
    }

    fn signed_block_header(&self) -> Option<&SignedBeaconBlockHeader> {
        None
    }

    fn into_partial(self) -> VerifiablePartialDataColumn<E> {
        self
    }

    fn as_full(
        &self,
        block: Option<&SignedBeaconBlock<E>>,
    ) -> Option<Cow<'_, DataColumnSidecar<E>>> {
        // we definitely require the block
        let block = block?;

        // we need to have all columns
        if !self.column.sidecar.is_complete() {
            return None;
        }

        // we need to have the correct amount of everything
        let expected = self.column.sidecar.cells_present_bitmap.len();
        if self.column.sidecar.column.len() != expected
            || self.column.sidecar.kzg_proofs.len() != expected
            || self.kzg_commitments.len() != expected
        {
            return None;
        }

        let (signed_block_header, kzg_commitments_inclusion_proof) =
            block.signed_block_header_and_kzg_commitments_proof().ok()?;
        Some(Cow::Owned(DataColumnSidecar {
            kzg_commitments_inclusion_proof,
            index: self.column.index,
            column: self.column.sidecar.column.clone(),
            kzg_commitments: self.kzg_commitments.clone(),
            kzg_proofs: self.column.sidecar.kzg_proofs.clone(),
            signed_block_header,
        }))
    }

    fn iter(&self) -> impl Iterator<Item = Option<CellWithMetadata<'_, E>>> {
        let sidecar = &self.column.sidecar;
        let mut present_iterator = sidecar
            .column
            .iter()
            .zip(self.kzg_commitments.iter())
            .zip(sidecar.kzg_proofs.iter())
            .map(|((cell, commitment), proof)| CellWithMetadata {
                cell,
                commitment,
                proof,
            });
        sidecar.cells_present_bitmap.iter().map(move |present| {
            if present {
                present_iterator.next()
            } else {
                None
            }
        })
    }
}
