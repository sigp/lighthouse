use crate::{
    block::{BLOB_KZG_COMMITMENTS_INDEX, SignedBeaconBlock, SignedBeaconBlockHeader},
    core::{EthSpec, Hash256, ListRef, Slot},
    data::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarFulu},
    execution::AbstractExecPayload,
    kzg_ext::KzgCommitments,
    state::BeaconStateError,
};
use educe::Educe;
use kzg::KzgProof;
use merkle_proof::verify_merkle_proof;
use ssz::BitList;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use ssz_types::{FixedVector, ListEncodedOption, ProgressiveVariableList, VariableList};
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
    #[superstruct(only(Fulu), partial_getter(rename = "column_fulu"))]
    pub column: VariableList<Cell<E>, E::MaxBlobCommitmentsPerBlock>,
    // [Modified in Gloas:EIP7688]
    #[superstruct(only(Gloas), partial_getter(rename = "column_gloas"))]
    pub column: ProgressiveVariableList<Cell<E>>,
    #[superstruct(only(Fulu), partial_getter(rename = "kzg_proofs_fulu"))]
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    // [Modified in Gloas:EIP7688]
    #[superstruct(only(Gloas), partial_getter(rename = "kzg_proofs_gloas"))]
    pub kzg_proofs: ProgressiveVariableList<KzgProof>,
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

/// Walks dense cell storage, pairing each set bit of `bitmap` with the cell and the proof held at
/// the matching storage position.
///
/// Cells are stored densely, so the nth set bit owns the nth cell and the nth proof. `zip` stops
/// at the shortest side, so storage that breaks that length invariant yields fewer items instead
/// of panicking.
fn zip_present_cells<'a, N: Unsigned, C: 'a, P: 'a>(
    bitmap: &'a BitList<N>,
    cells: impl Iterator<Item = C> + 'a,
    proofs: impl Iterator<Item = P> + 'a,
) -> impl Iterator<Item = (usize, C, P)> + 'a {
    bitmap
        .iter()
        .enumerate()
        .filter_map(|(blob_idx, present)| present.then_some(blob_idx))
        .zip(cells.zip(proofs))
        .map(|(blob_idx, (cell, proof))| (blob_idx, cell, proof))
}

impl<'a, E: EthSpec> PartialDataColumnView<'a, E> {
    /// Iterates over the present cells as `(blob_index, cell, proof)`, ascending by blob index.
    ///
    /// Storage is dense, exactly as described on [`PartialDataColumnSidecarRef::present_cells`].
    pub fn present_cells(&self) -> impl Iterator<Item = (usize, &'a Cell<E>, &'a KzgProof)> + '_ {
        zip_present_cells(
            self.cells_present_bitmap(),
            self.column().iter().copied(),
            self.kzg_proofs().iter().copied(),
        )
    }
}

impl<'a, E: EthSpec> PartialDataColumnSidecarRef<'a, E> {
    /// Unified view over the `column` field across forks (EIP-7688).
    pub fn column(&self) -> ListRef<'a, Cell<E>, E::MaxBlobCommitmentsPerBlock> {
        match self {
            Self::Fulu(sidecar) => ListRef::Basic(&sidecar.column),
            Self::Gloas(sidecar) => ListRef::Progressive(&sidecar.column),
        }
    }

    /// Unified view over the `kzg_proofs` field across forks (EIP-7688).
    pub fn kzg_proofs(&self) -> ListRef<'a, KzgProof, E::MaxBlobCommitmentsPerBlock> {
        match self {
            Self::Fulu(sidecar) => ListRef::Basic(&sidecar.kzg_proofs),
            Self::Gloas(sidecar) => ListRef::Progressive(&sidecar.kzg_proofs),
        }
    }

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

    /// Return a sparse view to the data within: If cell `n` is present, the returned `Vec` will
    /// contain the cell and proof at index `n`, or else `None`.
    pub fn as_sparse(&self) -> Vec<Option<(&'a Cell<E>, &'a KzgProof)>> {
        let mut ret = Vec::with_capacity(self.cells_present_bitmap().len());
        let mut iter = self.column().iter().zip(self.kzg_proofs().iter());
        for present in self.cells_present_bitmap().iter() {
            if present {
                ret.push(iter.next());
            } else {
                ret.push(None);
            }
        }
        ret
    }

    /// Iterates over the present cells as `(blob_index, cell, proof)`, ascending by blob index.
    ///
    /// Cells are stored densely, so the nth set bit of `cells_present_bitmap` owns the nth entry
    /// of `column` and of `kzg_proofs`. This iterator assumes that length invariant and yields
    /// fewer items than there are set bits when a sidecar violates it. Callers that need an error
    /// on a malformed sidecar call [`Self::verify_len`] first.
    pub fn present_cells(&self) -> impl Iterator<Item = (usize, &'a Cell<E>, &'a KzgProof)> + '_ {
        zip_present_cells(
            self.cells_present_bitmap(),
            self.column().iter(),
            self.kzg_proofs().iter(),
        )
    }

    /// Creates a reference to this sidecar containing only the blob indices for which the passed
    /// closure returns `true` and is present in `self`. Will return `None` if there is no overlap.
    ///
    /// The bitmap keeps its length and bit positions. This function unsets bits and does not
    /// compact them, so each kept cell still maps to its KZG commitment by blob index.
    pub fn try_filter<F, Err>(&self, filter: F) -> Result<Option<PartialDataColumnView<'a, E>>, Err>
    where
        F: Fn(usize, &Cell<E>, &KzgProof) -> Result<bool, Err>,
        Err: From<PartialDataColumnSidecarError>,
    {
        let len = self.verify_len()?;

        let mut new_bitmap = self.cells_present_bitmap().clone();
        let mut new_column = Vec::with_capacity(len);
        let mut new_proofs = Vec::with_capacity(len);

        for (blob_idx, cell, proof) in self.present_cells() {
            if filter(blob_idx, cell, proof)? {
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
}

impl<E: EthSpec> PartialDataColumnSidecar<E> {
    /// Unified view over the `column` field across forks (EIP-7688).
    pub fn column(&self) -> ListRef<'_, Cell<E>, E::MaxBlobCommitmentsPerBlock> {
        self.to_ref().column()
    }

    /// Unified view over the `kzg_proofs` field across forks (EIP-7688).
    pub fn kzg_proofs(&self) -> ListRef<'_, KzgProof, E::MaxBlobCommitmentsPerBlock> {
        self.to_ref().kzg_proofs()
    }

    pub fn is_complete(&self) -> bool {
        self.to_ref().is_complete()
    }

    pub fn get(&self, idx: usize) -> Option<(&Cell<E>, &KzgProof)> {
        self.to_ref().get(idx)
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

    fn make_sidecar_fulu(
        total_blobs: usize,
        present_indices: &[usize],
        marker_base: u8,
    ) -> PartialDataColumnSidecarFulu<E> {
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
    }

    fn make_sidecar_with_marker(
        total_blobs: usize,
        present_indices: &[usize],
        marker_base: u8,
    ) -> PartialDataColumnSidecar<E> {
        make_sidecar_fulu(total_blobs, present_indices, marker_base).into()
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
        let filtered = sidecar
            .to_ref()
            .try_filter::<_, PartialDataColumnSidecarError>(|idx, _, _| Ok(idx == 0 || idx == 4))
            .unwrap()
            .unwrap();
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
                .to_ref()
                .try_filter::<_, PartialDataColumnSidecarError>(
                    |idx, _, _| Ok(idx == 1 || idx == 3)
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn filter_preserves_all_when_all_match() {
        let sidecar = make_sidecar(6, &[0, 2, 4]);
        let filtered = sidecar
            .to_ref()
            .try_filter::<_, PartialDataColumnSidecarError>(|_, _, _| Ok(true))
            .unwrap()
            .unwrap();
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

    // -- try_clone_full tests (on PartialDataColumnFulu) --

    #[test]
    fn try_clone_full_succeeds_when_complete() {
        let sidecar = make_sidecar_fulu(3, &[0, 1, 2], 0);
        let header = make_header(3);
        let partial = PartialDataColumnFulu {
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
        let sidecar = make_sidecar_fulu(4, &[0, 2], 0);
        let header = make_header(4);
        let partial = PartialDataColumnFulu {
            block_root: Hash256::zero(),
            index: 0,
            sidecar,
        };
        assert!(partial.try_clone_full(&header).is_none());
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

    // -- present_cells tests --

    #[test]
    fn present_cells_pairs_sparse_bitmap() {
        let sidecar = make_sidecar_with_marker(7, &[1, 3, 5], 0);
        let present: Vec<_> = sidecar
            .to_ref()
            .present_cells()
            .map(|(blob_idx, cell, _)| (blob_idx, cell[0]))
            .collect();
        assert_eq!(present, vec![(1, 1), (3, 3), (5, 5)]);
    }
}
