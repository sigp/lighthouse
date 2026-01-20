use crate::test_utils::TestRandom;
use crate::{Cell, ColumnIndex, EthSpec, Hash256, KzgCommitments, SignedBeaconBlockHeader};
use educe::Educe;
use kzg::KzgProof;
use ssz::{BitList, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;
use typenum::U1;

pub type CellBitmap<E> = BitList<<E as EthSpec>::MaxBlobCommitmentsPerBlock>;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Encode, Decode, TreeHash, TestRandom, Educe)]
#[educe(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct PartialDataColumnSidecar<E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    pub column: VariableList<Arc<Cell<E>>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    pub header: VariableList<PartialDataColumnHeader<E>, U1>,
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            cells_present_bitmap: BitList::with_capacity(1).unwrap(),
            column: VariableList::new(vec![Arc::new(Cell::<E>::default())]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
            header: VariableList::new(vec![]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn size(present_blobs: usize, block_blobs: usize) -> usize {
        // min size is one cell
        Self {
            cells_present_bitmap: BitList::with_capacity(block_blobs).unwrap(),
            column: VariableList::new(vec![Default::default(); present_blobs]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); present_blobs]).unwrap(),
            header: VariableList::new(vec![]).unwrap(), // header is not being sent on cell push
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            cells_present_bitmap: BitList::with_capacity(max_blobs_per_block).unwrap(),
            column: VariableList::new(vec![Default::default(); max_blobs_per_block]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
            header: VariableList::new(vec![]).unwrap(), // header is not being sent on cell push
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
            header: self.header.clone(),
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
            header: if !self.header.is_empty() {
                self.header.clone()
            } else {
                other.header.clone()
            },
        })
    }
}

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Encode, Decode, TreeHash, TestRandom, Educe)]
#[educe(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct PartialDataColumnHeader<E: EthSpec> {
    pub kzg_commitments: KzgCommitments<E>,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
}

// TODO(dknopik): Name?
#[derive(Debug, Clone, PartialEq)]
pub struct DanglingPartialDataColumn<E: EthSpec> {
    pub block_root: Hash256,
    pub index: ColumnIndex,
    pub sidecar: PartialDataColumnSidecar<E>,
}

impl<E: EthSpec> DanglingPartialDataColumn<E> {
    pub fn clone_filter<F>(&self, filter: F) -> Option<Self>
    where
        F: Fn(usize) -> bool,
    {
        Some(DanglingPartialDataColumn {
            sidecar: self.sidecar.clone_filter(filter)?,
            block_root: self.block_root,
            index: self.index,
        })
    }
}
