use std::sync::Arc;

use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    block::{BLOB_KZG_COMMITMENTS_INDEX, BeaconBlockHeader, SignedBeaconBlockHeader},
    core::{Epoch, EthSpec, Hash256, Slot},
    data::{
        CellBitmap, PartialDataColumn, PartialDataColumnHeader, PartialDataColumnSidecar,
        PartialDataColumnSidecarError, PartialDataColumnSidecarRef,
    },
    fork::ForkName,
    kzg_ext::{KzgCommitments, KzgError},
    state::BeaconStateError,
};

pub type ColumnIndex = u64;
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::BytesPerCell>;
pub type DataColumn<E> = VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Identifies a set of data columns associated with a specific beacon block.
#[derive(Encode, Decode, Clone, Debug, PartialEq, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
pub struct DataColumnsByRootIdentifier<E: EthSpec> {
    pub block_root: Hash256,
    pub columns: VariableList<ColumnIndex, E::NumberOfColumns>,
}

pub type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

#[superstruct(
    variants(Fulu, Gloas),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            Educe,
            TreeHash,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec")
        )
    ),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "DataColumnSidecarError", expr = "DataColumnSidecarError::IncorrectStateVariant"),
    partial_getter_error(ty = "DataColumnSidecarError", expr = "DataColumnSidecarError::IncorrectStateVariant")
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, Educe, Deserialize)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged, deny_unknown_fields)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct DataColumnSidecar<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: ColumnIndex,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<E>,
    /// All the KZG commitments associated with the block, used for verifying sample cells.
    /// In Gloas, commitments come from `block.body.signed_execution_payload_bid.message.blob_kzg_commitments`.
    #[superstruct(only(Fulu))]
    pub kzg_commitments: KzgCommitments<E>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    #[superstruct(only(Fulu))]
    pub signed_block_header: SignedBeaconBlockHeader,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    #[superstruct(only(Fulu))]
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
    #[superstruct(only(Gloas), partial_getter(rename = "slot_gloas"))]
    pub slot: Slot,
    #[superstruct(only(Gloas))]
    pub beacon_block_root: Hash256,
}

impl<E: EthSpec> DataColumnSidecar<E> {
    pub fn slot(&self) -> Slot {
        match self {
            DataColumnSidecar::Fulu(column) => column.slot(),
            DataColumnSidecar::Gloas(column) => column.slot,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn block_root(&self) -> Hash256 {
        match self {
            DataColumnSidecar::Fulu(column) => column.block_root(),
            DataColumnSidecar::Gloas(column) => column.beacon_block_root,
        }
    }

    /// Custom SSZ decoder that takes a `ForkName` as context.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra => Err(ssz::DecodeError::NoMatchingVariant),
            ForkName::Fulu => Ok(DataColumnSidecar::Fulu(
                DataColumnSidecarFulu::from_ssz_bytes(bytes)?,
            )),
            ForkName::Gloas => Ok(DataColumnSidecar::Gloas(
                DataColumnSidecarGloas::from_ssz_bytes(bytes)?,
            )),
        }
    }

    /// Convert this full data column into a partial data column reference for KZG verification.
    /// The header will NOT be set.
    ///
    /// Uses the supplied filter to determine which cells to include in the partial sidecar.
    pub fn try_filter_to_partial_ref<F, Err>(
        &self,
        filter: F,
    ) -> Result<Option<PartialDataColumnSidecarRef<'_, E>>, Err>
    where
        F: Fn(usize, &Cell<E>, &KzgProof) -> Result<bool, Err>,
        Err: From<PartialDataColumnSidecarError>,
    {
        let len = self.column().len();
        let mut new_bitmap = CellBitmap::<E>::with_capacity(len)
            .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?;
        let mut new_column = Vec::with_capacity(len);
        let mut new_proofs = Vec::with_capacity(len);
        let iter = self.column().iter().zip(self.kzg_proofs().iter());

        for (blob_idx, (cell, proof)) in iter.enumerate() {
            if filter(blob_idx, cell, proof)? {
                // Keep this cell
                new_column.push(cell);
                new_proofs.push(proof);
                // Mark as present
                new_bitmap
                    .set(blob_idx, true)
                    .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?;
            }
        }

        if new_column.is_empty() {
            return Ok(None);
        }

        Ok(Some(PartialDataColumnSidecarRef {
            cells_present_bitmap: new_bitmap,
            column: new_column,
            kzg_proofs: new_proofs,
            header: None.into(),
        }))
    }
}

impl<E: EthSpec> DataColumnSidecarFulu<E> {
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

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default(); max_blobs_per_block]).unwrap(),
            kzg_commitments: VariableList::new(vec![
                KzgCommitment::empty_for_testing();
                max_blobs_per_block
            ])
            .unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
        .len()
    }

    /// Convert this full data column into a verifiable partial data column.
    pub fn to_partial(&self) -> PartialDataColumn<E> {
        let cell_count = self.column.len();
        let mut bitmap =
            CellBitmap::<E>::with_capacity(cell_count).expect("our column has the same bound");
        for idx in 0..cell_count {
            bitmap
                .set(idx, true)
                .expect("The correct size is initialized right above");
        }

        let block_root = self.block_root();

        PartialDataColumn {
            block_root,
            index: self.index,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: bitmap,
                column: self.column.clone(),
                kzg_proofs: self.kzg_proofs.clone(),
                header: Some(PartialDataColumnHeader {
                    kzg_commitments: self.kzg_commitments.clone(),
                    signed_block_header: self.signed_block_header.clone(),
                    kzg_commitments_inclusion_proof: self.kzg_commitments_inclusion_proof.clone(),
                })
                .into(),
            },
        }
    }
}

impl<E: EthSpec> DataColumnSidecarGloas<E> {
    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
            slot: Slot::new(0),
            beacon_block_root: Hash256::ZERO,
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default(); max_blobs_per_block]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
            slot: Slot::new(0),
            beacon_block_root: Hash256::ZERO,
        }
        .as_ssz_bytes()
        .len()
    }
}

#[derive(Debug)]
pub enum DataColumnSidecarError {
    ArithError(ArithError),
    BeaconStateError(BeaconStateError),
    DataColumnIndexOutOfBounds,
    KzgCommitmentInclusionProofOutOfBounds,
    KzgError(KzgError),
    KzgNotInitialized,
    MissingBlobSidecars,
    PreDeneb,
    SszError(SszError),
    BuildSidecarFailed(String),
    InvalidCellProofLength { expected: usize, actual: usize },
    IncorrectStateVariant,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{MainnetEthSpec, max_data_columns_by_root_request_common};
    use fixed_bytes::FixedBytesExtended;
    use ssz_types::RuntimeVariableList;

    // This is the "correct" implementation of max_data_columns_by_root_request.
    // This test ensures that the simplified implementation doesn't deviate from it.
    fn max_data_columns_by_root_request_implementation<E: EthSpec>(
        max_request_blocks: u64,
    ) -> usize {
        let max_request_blocks = max_request_blocks as usize;

        let empty_data_columns_by_root_id = DataColumnsByRootIdentifier {
            block_root: Hash256::zero(),
            columns: VariableList::repeat_full(0),
        };

        RuntimeVariableList::<DataColumnsByRootIdentifier<E>>::new(
            vec![empty_data_columns_by_root_id; max_request_blocks],
            max_request_blocks,
        )
        .expect("creating a RuntimeVariableList of size `max_request_blocks` should succeed")
        .as_ssz_bytes()
        .len()
    }

    #[test]
    fn max_data_columns_by_root_request_matches_simplified() {
        for n in [0, 1, 2, 8, 16, 32, 64, 128, 256, 512, 1024] {
            assert_eq!(
                max_data_columns_by_root_request_common::<MainnetEthSpec>(n),
                max_data_columns_by_root_request_implementation::<MainnetEthSpec>(n),
                "Mismatch at n={n}"
            );
        }
    }
}
