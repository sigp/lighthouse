use crate::{
    block::{BLOB_KZG_COMMITMENTS_INDEX, SignedBeaconBlock, SignedBeaconBlockHeader},
    core::{EthSpec, Hash256, Slot},
    data::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarFulu, DataColumnSidecarGloas},
    execution::AbstractExecPayload,
    kzg_ext::KzgCommitments,
    state::BeaconStateError,
};
use educe::Educe;
use kzg::KzgProof;
use merkle_proof::verify_merkle_proof;
use ssz::BitList;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, ListEncodedOption, VariableList};
use std::fmt::Display;
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type CellBitmap<E> = BitList<<E as EthSpec>::MaxBlobCommitmentsPerBlock>;

#[superstruct(
    variants(Fulu, Gloas),
    variant_attributes(
        derive(Debug, Clone, Encode, Decode, TreeHash, Educe),
        educe(PartialEq, Eq, Hash(bound = "E: EthSpec")),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec")
        ),
    ),
    ref_attributes(
        derive(Debug, PartialEq, TreeHash),
        tree_hash(enum_behaviour = "transparent")
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Encode, Decode, TreeHash, Educe)]
#[educe(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct PartialDataColumnSidecar<E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    pub column: VariableList<Cell<E>, E::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    #[superstruct(only(Fulu))]
    pub header: ListEncodedOption<PartialDataColumnHeader<E>>,
}

/// Equivalent to `PartialDataColumnSidecar`, but containing references to the cells. This is done
/// so that we can get a part of a sidecar without expensively cloning all the contents.
#[superstruct(
    variants(Fulu, Gloas),
    variant_attributes(derive(Debug, Clone, Encode),),
    ref_attributes(derive(Debug),)
)]
#[derive(Debug, Clone, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct PartialDataColumnView<'a, E: EthSpec> {
    pub cells_present_bitmap: CellBitmap<E>,
    // It is fine to use `Vec` here as we never decode directly into this type, and only create
    // this from the `PartialDataColumnSidecar` type above. This avoids a few ugly `expect` calls.
    pub column: Vec<&'a Cell<E>>,
    pub kzg_proofs: Vec<&'a KzgProof>,
    #[superstruct(only(Fulu))]
    pub header: ListEncodedOption<&'a PartialDataColumnHeader<E>>,
}

#[derive(Debug, Clone, Copy)]
pub enum PartialDataColumnSidecarError {
    UnexpectedBounds,
    InternallyInconsistent,
    DifferingLengths { lhs_len: usize, rhs_len: usize },
    ConflictingData,
}

impl<'a, E: EthSpec> PartialDataColumnSidecarRef<'a, E> {
    pub fn is_complete(&self) -> bool {
        self.cells_present_bitmap().num_set_bits() == self.cells_present_bitmap().len()
    }

    pub fn get(&self, idx: usize) -> Option<(&'a Cell<E>, &'a KzgProof)> {
        if !self.cells_present_bitmap().get(idx).unwrap_or(false) {
            return None;
        }
        let storage_idx = self
            .cells_present_bitmap()
            .iter()
            .take(idx)
            .filter(|b| *b)
            .count();
        self.column()
            .get(storage_idx)
            .zip(self.kzg_proofs().get(storage_idx))
    }

    /// Creates a reference to this sidecar containing only the blob indices for which the passed
    /// closure returns `true` and is present in `self`. Will return `None` if there is no overlap.
    pub fn filter<F>(
        &self,
        filter: F,
    ) -> Result<Option<PartialDataColumnView<'a, E>>, PartialDataColumnSidecarError>
    where
        F: Fn(usize) -> bool,
    {
        let len = self.verify_len()?;

        let mut new_bitmap = self.cells_present_bitmap().clone();
        let mut new_column = Vec::with_capacity(len);
        let mut new_proofs = Vec::with_capacity(len);
        let mut iter = self.column().iter().zip(self.kzg_proofs().iter());

        for (blob_idx, present) in self.cells_present_bitmap().iter().enumerate() {
            if present {
                let (cell, proof) = iter
                    .next()
                    .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                if filter(blob_idx) {
                    // Keep this cell
                    new_column.push(cell);
                    new_proofs.push(proof);
                } else {
                    // Mark as not present
                    new_bitmap
                        .set(blob_idx, false)
                        .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?;
                }
            }
        }

        if new_column.is_empty() {
            return Ok(None);
        }

        Ok(Some(if let Ok(header) = self.header() {
            PartialDataColumnViewFulu {
                cells_present_bitmap: new_bitmap,
                column: new_column,
                kzg_proofs: new_proofs,
                header: header.as_ref().into(),
            }
            .into()
        } else {
            PartialDataColumnViewGloas {
                cells_present_bitmap: new_bitmap,
                column: new_column,
                kzg_proofs: new_proofs,
            }
            .into()
        }))
    }

    pub fn verify_len(&self) -> Result<usize, PartialDataColumnSidecarError> {
        let len = self.cells_present_bitmap().num_set_bits();
        if len != self.kzg_proofs().len() || len != self.column().len() {
            return Err(PartialDataColumnSidecarError::InternallyInconsistent);
        }
        Ok(len)
    }

    /// Merge the cells of two partial sidecars into their combined bitmap, column, and proofs.
    ///
    /// Both sidecars must be internally consistent (see [`Self::verify_len`]) and have bitmaps of
    /// the same length. If both contain the same cell, the cell from `self` is kept — though as
    /// they are KZG verified, the two will be identical.
    ///
    /// Only the fork-agnostic fields are merged, so the result is returned as a (header-less)
    /// [`PartialDataColumnSidecarGloas`]. The caller is responsible for any fork-specific fields
    /// (e.g. the Fulu header) when assembling the resulting sidecar.
    pub fn merge_without_header(
        &self,
        other: &Self,
    ) -> Result<PartialDataColumnSidecarGloas<E>, PartialDataColumnSidecarError> {
        // Check that each sidecar is internally consistent by checking the lengths.
        self.verify_len()?;
        other.verify_len()?;
        if self.cells_present_bitmap().len() != other.cells_present_bitmap().len() {
            return Err(PartialDataColumnSidecarError::DifferingLengths {
                lhs_len: self.cells_present_bitmap().len(),
                rhs_len: other.cells_present_bitmap().len(),
            });
        }

        let new_bitmap = self
            .cells_present_bitmap()
            .union(other.cells_present_bitmap());
        let len = new_bitmap.num_set_bits();
        let mut new_column = Vec::with_capacity(len);
        let mut new_proofs = Vec::with_capacity(len);
        let mut self_iter = self.column().iter().zip(self.kzg_proofs().iter());
        let mut other_iter = other.column().iter().zip(other.kzg_proofs().iter());

        for presence_bits in self
            .cells_present_bitmap()
            .iter()
            .zip(other.cells_present_bitmap().iter())
        {
            match presence_bits {
                (false, false) => {}
                (true, other_present) => {
                    let (cell, proof) = self_iter
                        .next()
                        .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    new_column.push(cell.clone());
                    new_proofs.push(*proof);
                    if other_present {
                        other_iter
                            .next()
                            .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    }
                }
                (false, true) => {
                    let (cell, proof) = other_iter
                        .next()
                        .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    new_column.push(cell.clone());
                    new_proofs.push(*proof);
                }
            }
        }

        Ok(PartialDataColumnSidecarGloas {
            cells_present_bitmap: new_bitmap,
            column: new_column
                .try_into()
                .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?,
            kzg_proofs: new_proofs
                .try_into()
                .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?,
        })
    }
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
    pub fn is_complete(&self) -> bool {
        self.to_ref().is_complete()
    }

    pub fn get(&self, idx: usize) -> Option<(&Cell<E>, &KzgProof)> {
        self.to_ref().get(idx)
    }

    pub fn filter<F>(
        &self,
        filter: F,
    ) -> Result<Option<PartialDataColumnView<'_, E>>, PartialDataColumnSidecarError>
    where
        F: Fn(usize) -> bool,
    {
        self.to_ref().filter(filter)
    }

    pub fn verify_len(&self) -> Result<usize, PartialDataColumnSidecarError> {
        self.to_ref().verify_len()
    }
}

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Encode, Decode, TreeHash, Educe)]
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
                .kzg_commitments_merkle_proof()?,
        })
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct PartialDataColumnPartsMetadata<E: EthSpec> {
    pub available: CellBitmap<E>,
    pub requests: CellBitmap<E>,
}

impl<E: EthSpec> Display for PartialDataColumnPartsMetadata<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(available: {}, requested: {})",
            self.available, self.requests
        )
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct PartialDataColumnGroupId {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
}

#[superstruct(
    variants(Fulu, Gloas),
    variant_attributes(derive(Debug, Clone, PartialEq)),
    ref_attributes(derive(Debug))
)]
#[derive(Debug, Clone, PartialEq)]
pub struct PartialDataColumn<E: EthSpec> {
    pub block_root: Hash256,
    #[superstruct(only(Gloas))]
    pub slot: Slot,
    pub index: ColumnIndex,
    #[superstruct(only(Fulu), partial_getter(rename = "sidecar_fulu"))]
    pub sidecar: PartialDataColumnSidecarFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "sidecar_gloas"))]
    pub sidecar: PartialDataColumnSidecarGloas<E>,
}

impl<E: EthSpec> PartialDataColumn<E> {
    pub fn sidecar(&self) -> PartialDataColumnSidecarRef<'_, E> {
        self.to_ref().sidecar()
    }

    /// Equivalent to a call to `clone` followed by `try_into_full`, but returns early if conversion
    /// is not possible.
    pub fn try_clone_full(
        &self,
        header: Option<&PartialDataColumnHeader<E>>,
    ) -> Option<DataColumnSidecar<E>> {
        match self {
            PartialDataColumn::Fulu(fulu) => fulu.try_clone_full(header?),
            PartialDataColumn::Gloas(gloas) => gloas.try_clone_full(),
        }
    }

    pub fn try_into_full(
        self,
        header: Option<&PartialDataColumnHeader<E>>,
    ) -> Option<DataColumnSidecar<E>> {
        match self {
            PartialDataColumn::Fulu(fulu) => fulu.try_into_full(header?),
            PartialDataColumn::Gloas(gloas) => gloas.try_into_full(),
        }
    }
}

impl<E: EthSpec> PartialDataColumnFulu<E> {
    fn is_complete(&self) -> bool {
        PartialDataColumnSidecarRef::Fulu(&self.sidecar).is_complete()
    }

    /// Equivalent to a call to `clone` followed by [`Self::try_into_full`], but returns early if
    /// conversion is not possible.
    pub fn try_clone_full(
        &self,
        header: &PartialDataColumnHeader<E>,
    ) -> Option<DataColumnSidecar<E>> {
        if !self.is_complete() {
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
        if !self.is_complete() {
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

impl<E: EthSpec> PartialDataColumnGloas<E> {
    fn is_complete(&self) -> bool {
        PartialDataColumnSidecarRef::Gloas(&self.sidecar).is_complete()
    }

    /// Equivalent to a call to `clone` followed by [`Self::try_into_full`], but returns early if
    /// conversion is not possible.
    pub fn try_clone_full(&self) -> Option<DataColumnSidecar<E>> {
        if !self.is_complete() {
            return None;
        }
        Some(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index: self.index,
            column: self.sidecar.column.clone(),
            kzg_proofs: self.sidecar.kzg_proofs.clone(),
            slot: self.slot,
            beacon_block_root: self.block_root,
        }))
    }

    pub fn try_into_full(self) -> Option<DataColumnSidecar<E>> {
        if !self.is_complete() {
            return None;
        }
        Some(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index: self.index,
            column: self.sidecar.column,
            kzg_proofs: self.sidecar.kzg_proofs,
            slot: self.slot,
            beacon_block_root: self.block_root,
        }))
    }
}

impl<'a, E: EthSpec> PartialDataColumnRef<'a, E> {
    pub fn sidecar(&self) -> PartialDataColumnSidecarRef<'a, E> {
        match self {
            PartialDataColumnRef::Fulu(f) => PartialDataColumnSidecarRef::Fulu(&f.sidecar),
            PartialDataColumnRef::Gloas(g) => PartialDataColumnSidecarRef::Gloas(&g.sidecar),
        }
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

        PartialDataColumnSidecarFulu {
            cells_present_bitmap: bitmap,
            column,
            kzg_proofs: proofs,
            header: None.into(),
        }
        .into()
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
        let filtered = sidecar.filter(|idx| idx == 0 || idx == 4).unwrap().unwrap();
        assert_eq!(filtered.column().len(), 2);
        assert_eq!(filtered.kzg_proofs().len(), 2);
        assert!(filtered.cells_present_bitmap().get(0).unwrap());
        assert!(!filtered.cells_present_bitmap().get(2).unwrap());
        assert!(filtered.cells_present_bitmap().get(4).unwrap());
    }

    #[test]
    fn filter_returns_none_when_no_overlap() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        assert!(
            sidecar
                .filter(|idx| idx == 1 || idx == 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn filter_preserves_all_when_all_match() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        let filtered = sidecar.filter(|_| true).unwrap().unwrap();
        assert_eq!(filtered.column().len(), 3);
        assert_eq!(filtered.kzg_proofs().len(), 3);
        assert_eq!(
            filtered.cells_present_bitmap(),
            sidecar.cells_present_bitmap()
        );

        // Also, check that the encoded version matches
        assert_eq!(filtered.as_ssz_bytes(), sidecar.as_ssz_bytes());
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

    fn into_fulu(sidecar: PartialDataColumnSidecar<E>) -> PartialDataColumnSidecarFulu<E> {
        match sidecar {
            PartialDataColumnSidecar::Fulu(s) => s,
            PartialDataColumnSidecar::Gloas(_) => panic!("expected Fulu sidecar"),
        }
    }

    #[test]
    fn try_clone_full_succeeds_when_complete() {
        let sidecar = make_sidecar(3, &[0, 1, 2]);
        let header = make_header(3);
        let partial: PartialDataColumn<E> = PartialDataColumnFulu {
            block_root: Hash256::zero(),
            index: 5,
            sidecar: into_fulu(sidecar),
        }
        .into();
        let full = partial.try_clone_full(Some(&header)).unwrap();
        assert_eq!(*full.index(), 5);
        assert_eq!(full.column().len(), 3);
    }

    #[test]
    fn try_clone_full_returns_none_when_incomplete() {
        let sidecar = make_sidecar(4, &[0, 2]);
        let header = make_header(4);
        let partial: PartialDataColumn<E> = PartialDataColumnFulu {
            block_root: Hash256::zero(),
            index: 0,
            sidecar: into_fulu(sidecar),
        }
        .into();
        assert!(partial.try_clone_full(Some(&header)).is_none());
    }

    // -- get tests --

    #[test]
    fn get_sparse_bitmap_maps_to_correct_storage_position() {
        // bitmap: [false, true, false, true] → column: [cell_1, cell_3]
        let sidecar = make_sidecar_with_marker(4, &[1, 3], 0);
        let (cell, _) = sidecar.get(1).expect("cell at blob index 1 should exist");
        assert_eq!(cell[0], 1);
        let (cell, _) = sidecar.get(3).expect("cell at blob index 3 should exist");
        assert_eq!(cell[0], 3);
    }

    #[test]
    fn get_absent_blob_index_returns_none() {
        let sidecar = make_sidecar(4, &[1, 3]);
        assert!(sidecar.get(0).is_none());
        assert!(sidecar.get(2).is_none());
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let sidecar = make_sidecar(4, &[0, 2]);
        assert!(sidecar.get(4).is_none());
        assert!(sidecar.get(100).is_none());
    }

    #[test]
    fn get_dense_bitmap_matches_direct_index() {
        let sidecar = make_sidecar_with_marker(4, &[0, 1, 2, 3], 10);
        for i in 0..4 {
            let (cell, _) = sidecar.get(i).expect("all cells should be present");
            assert_eq!(cell[0], 10 + i as u8);
        }
    }
}
