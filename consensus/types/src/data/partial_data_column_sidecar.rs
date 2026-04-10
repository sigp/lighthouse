use crate::test_utils::TestRandom;
use crate::{
    AbstractExecPayload, BLOB_KZG_COMMITMENTS_INDEX, BeaconStateError, Cell, ColumnIndex,
    DataColumnSidecar, DataColumnSidecarFulu, EthSpec, Hash256, KzgCommitments, SignedBeaconBlock,
    SignedBeaconBlockHeader, Slot,
};
use educe::Educe;
use kzg::KzgProof;
use merkle_proof::verify_merkle_proof;
use ssz::BitList;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, ListEncodedOption, VariableList};
use std::fmt::Display;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type CellBitmap<E> = BitList<<E as EthSpec>::MaxBlobCommitmentsPerBlock>;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Encode, Decode, TreeHash, Educe)]
#[educe(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct PartialDataColumnSidecar<E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    pub column: VariableList<Cell<E>, E::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    pub header: ListEncodedOption<PartialDataColumnHeader<E>>,
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
    pub header: ListEncodedOption<&'a PartialDataColumnHeader<E>>,
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
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
            header: self.header.as_ref().into(),
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
            header: if !self.header.is_some() {
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
    /// Equivalent to a call to `clone` followed by `try_into_full`, but returns early if conversion
    /// is not possible.
    pub fn try_clone_full(
        &self,
        header: &PartialDataColumnHeader<E>,
    ) -> Option<DataColumnSidecar<E>> {
        if !self.sidecar.is_complete() {
            return None;
        }

        Some(DataColumnSidecar::Fulu(DataColumnSidecarFulu {
            index: self.index,
            column: self.sidecar.column.clone(),
            kzg_commitments: header.kzg_commitments.clone(),
            kzg_proofs: self.sidecar.kzg_proofs.clone(),
            signed_block_header: header.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof.clone(),
        }))
    }

    pub fn try_into_full(
        self,
        header: &PartialDataColumnHeader<E>,
    ) -> Option<DataColumnSidecar<E>> {
        if !self.sidecar.is_complete() {
            return None;
        }

        Some(DataColumnSidecar::Fulu(DataColumnSidecarFulu {
            index: self.index,
            column: self.sidecar.column,
            kzg_commitments: header.kzg_commitments.clone(),
            kzg_proofs: self.sidecar.kzg_proofs,
            signed_block_header: header.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinimalEthSpec;
    use bls::Signature;
    use fixed_bytes::FixedBytesExtended;
    use kzg::KzgCommitment;
    use ssz::Encode;

    type E = MinimalEthSpec;

    fn make_cell(marker: u8) -> Cell<E> {
        let mut cell = Cell::<E>::default();
        cell[0] = marker;
        cell
    }

    fn make_sidecar_with_marker(
        total_blobs: usize,
        present_indices: &[usize],
        marker_base: u8,
    ) -> PartialDataColumnSidecar<E> {
        let mut bitmap = CellBitmap::<E>::with_capacity(total_blobs).unwrap();
        for &idx in present_indices {
            bitmap.set(idx, true).unwrap();
        }

        let column: VariableList<_, _> = present_indices
            .iter()
            .map(|&idx| make_cell(marker_base.wrapping_add(idx as u8)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let proofs: VariableList<_, _> = present_indices
            .iter()
            .map(|_| KzgProof::empty())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        PartialDataColumnSidecar {
            cells_present_bitmap: bitmap,
            column,
            kzg_proofs: proofs,
            header: None.into(),
        }
    }

    fn make_sidecar(total_blobs: usize, present_indices: &[usize]) -> PartialDataColumnSidecar<E> {
        make_sidecar_with_marker(total_blobs, present_indices, 0)
    }

    fn make_header(num_commitments: usize) -> PartialDataColumnHeader<E> {
        PartialDataColumnHeader {
            kzg_commitments: vec![KzgCommitment([0u8; 48]); num_commitments]
                .try_into()
                .unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: crate::BeaconBlockHeader {
                    slot: Slot::new(0),
                    proposer_index: 0,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: FixedVector::new(
                vec![Hash256::zero(); E::kzg_commitments_inclusion_proof_depth()],
            )
            .unwrap(),
        }
    }

    // -- filter tests --

    #[test]
    fn filter_keeps_matching_cells() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        let filtered = sidecar.filter(|idx| idx == 0 || idx == 4).unwrap();
        assert_eq!(filtered.column.len(), 2);
        assert_eq!(filtered.kzg_proofs.len(), 2);
        assert!(filtered.cells_present_bitmap.get(0).unwrap());
        assert!(!filtered.cells_present_bitmap.get(2).unwrap());
        assert!(filtered.cells_present_bitmap.get(4).unwrap());
    }

    #[test]
    fn filter_returns_none_when_no_overlap() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        assert!(sidecar.filter(|idx| idx == 1 || idx == 3).is_none());
    }

    #[test]
    fn filter_preserves_all_when_all_match() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        let filtered = sidecar.filter(|_| true).unwrap();
        assert_eq!(filtered.column.len(), 3);
        assert_eq!(filtered.kzg_proofs.len(), 3);
        assert_eq!(filtered.cells_present_bitmap, sidecar.cells_present_bitmap);

        // Also, check that the encoded version matches
        assert_eq!(filtered.as_ssz_bytes(), sidecar.as_ssz_bytes());
    }

    // -- merge tests --

    #[test]
    fn merge_disjoint_partials() {
        let a = make_sidecar(6, &[0, 2]);
        let b = make_sidecar(6, &[1, 3]);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.column.len(), 4);
        assert_eq!(merged.kzg_proofs.len(), 4);
        for i in 0..4 {
            assert!(merged.cells_present_bitmap.get(i).unwrap());
        }
        assert!(!merged.cells_present_bitmap.get(4).unwrap());
    }

    #[test]
    fn merge_overlapping_partials_prefers_self() {
        let a = make_sidecar_with_marker(4, &[0, 1], 0);
        let b = make_sidecar_with_marker(4, &[1, 2], 100);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.column.len(), 3);
        // Cell at bitmap index 1 is the second cell in the merged column.
        // It should come from `a` (marker_base=0, so marker=0+1=1), not `b` (marker=100+1=101).
        assert_eq!(merged.column[1][0], 1);
    }

    #[test]
    fn merge_with_empty_other() {
        let a = make_sidecar(4, &[0, 2]);
        let b = make_sidecar(4, &[]);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.column.len(), 2);
        assert_eq!(merged.cells_present_bitmap, a.cells_present_bitmap);
    }

    #[test]
    fn merge_preserves_header_from_self() {
        let mut a = make_sidecar(4, &[0]);
        a.header = Some(make_header(4)).into();
        let b = make_sidecar(4, &[1]);
        let merged = a.merge(&b).unwrap();
        assert!(merged.header.is_some());

        // If self has no header, use other's
        let c = make_sidecar(4, &[0]);
        let mut d = make_sidecar(4, &[1]);
        d.header = Some(make_header(4)).into();
        let merged2 = c.merge(&d).unwrap();
        assert!(merged2.header.is_some());
    }

    // -- is_complete tests --

    #[test]
    fn is_complete_true_when_all_bits_set() {
        let sidecar = make_sidecar(4, &[0, 1, 2, 3]);
        assert!(sidecar.is_complete());
    }

    #[test]
    fn is_complete_false_when_partial() {
        let sidecar = make_sidecar(4, &[0, 2]);
        assert!(!sidecar.is_complete());
    }

    // -- try_clone_full tests (on PartialDataColumn) --

    #[test]
    fn try_clone_full_succeeds_when_complete() {
        let sidecar = make_sidecar(3, &[0, 1, 2]);
        let header = make_header(3);
        let partial = PartialDataColumn {
            block_root: Hash256::zero(),
            index: 5,
            sidecar,
        };
        let full = partial.try_clone_full(&header).unwrap();
        assert_eq!(*full.index(), 5);
        assert_eq!(full.column().len(), 3);
    }

    #[test]
    fn try_clone_full_returns_none_when_incomplete() {
        let sidecar = make_sidecar(4, &[0, 2]);
        let header = make_header(4);
        let partial = PartialDataColumn {
            block_root: Hash256::zero(),
            index: 0,
            sidecar,
        };
        assert!(partial.try_clone_full(&header).is_none());
    }
}
