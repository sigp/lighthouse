use crate::test_utils::TestRandom;
use crate::{
    AbstractExecPayload, BLOB_KZG_COMMITMENTS_INDEX, BeaconStateError, Cell, ColumnIndex,
    DataColumnSidecar, DataColumnSidecarFulu, EthSpec, Hash256, KzgCommitments, SignedBeaconBlock,
    SignedBeaconBlockHeader, Slot,
};
use educe::Educe;
use kzg::KzgProof;
use merkle_proof::verify_merkle_proof;
use ssz::{BitList, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::fmt::Display;
use std::mem;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
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
    pub column: VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    pub header: VariableList<PartialDataColumnHeader<E>, U1>,
}

/// Equivalent to `PartialDataColumnSidecar`, but containing references to the cells. This is done
/// so that we can get a part of a sidecar without expensively cloning all the contents.
#[derive(Debug, Clone, Encode)]
pub struct PartialDataColumnSidecarRef<'a, E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    // It is fine to use `Vec` here as we never decode directly into this type, and only create
    // this from the `PartialDataColumnSidecar` type above. This avoids a few ugly `expect` calls.
    pub column: Vec<&'a Cell<E>>,
    pub kzg_proofs: Vec<&'a KzgProof>,
    pub header: Vec<&'a PartialDataColumnHeader<E>>,
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            cells_present_bitmap: BitList::with_capacity(1).unwrap(),
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
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

    /// Creates a reference to this sidecar containing only the blob indices for which the passed
    /// closure returns `true` and is present in `self`. Will return `None` if there is no overlap.
    pub fn filter<F>(&self, filter: F) -> Option<PartialDataColumnSidecarRef<'_, E>>
    where
        F: Fn(usize) -> bool,
    {
        let mut new_bitmap = self.cells_present_bitmap.clone();
        let mut new_column = Vec::new();
        let mut new_proofs = Vec::new();
        let mut column_idx = 0;

        for (blob_idx, present) in self.cells_present_bitmap.iter().enumerate() {
            if present {
                if filter(blob_idx) {
                    // Keep this cell
                    let cell = self.column.get(column_idx)?;
                    new_column.push(cell);
                    let proof = self.kzg_proofs.get(column_idx)?;
                    new_proofs.push(proof);
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

        Some(PartialDataColumnSidecarRef {
            cells_present_bitmap: new_bitmap,
            column: new_column,
            kzg_proofs: new_proofs,
            header: self.header.iter().collect(),
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

    pub fn take_header(&mut self) -> Option<PartialDataColumnHeader<E>> {
        Vec::from(mem::take(&mut self.header)).pop()
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

impl<E: EthSpec> PartialDataColumnHeader<E> {
    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

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
}

impl<E: EthSpec, P: AbstractExecPayload<E>> TryFrom<&SignedBeaconBlock<E, P>>
    for PartialDataColumnHeader<E>
{
    type Error = BeaconStateError;

    fn try_from(block: &SignedBeaconBlock<E, P>) -> Result<Self, Self::Error> {
        Ok(Self {
            kzg_commitments: block.message().body().blob_kzg_commitments()?.clone(),
            signed_block_header: block.signed_block_header(),
            kzg_commitments_inclusion_proof: block
                .message()
                .body()
                .kzg_commitments_merkle_proof()?
                .clone(),
        })
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct PartialDataColumnPartsMetadata<E: EthSpec> {
    pub available: CellBitmap<E>,
    pub request: CellBitmap<E>,
}

impl<E: EthSpec> Display for PartialDataColumnPartsMetadata<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(available: {}, requested: {})",
            self.available, self.request
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartialDataColumn<E: EthSpec> {
    pub block_root: Hash256,
    pub index: ColumnIndex,
    pub sidecar: PartialDataColumnSidecar<E>,
}

impl<E: EthSpec> PartialDataColumn<E> {
    pub fn try_clone_full(&self) -> Option<DataColumnSidecar<E>> {
        if !self.sidecar.is_complete() {
            return None;
        }
        let Some(header) = self.sidecar.header.first() else {
            return None;
        };

        Some(DataColumnSidecar::Fulu(DataColumnSidecarFulu {
            index: self.index,
            column: self.sidecar.column.clone(),
            kzg_commitments: header.kzg_commitments.clone(),
            kzg_proofs: self.sidecar.kzg_proofs.clone(),
            signed_block_header: header.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof.clone(),
        }))
    }
}
