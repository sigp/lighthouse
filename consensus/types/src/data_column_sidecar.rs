use crate::beacon_block_body::{BLOB_KZG_COMMITMENTS_INDEX, KzgCommitments};
use crate::das_column::{CellWithMetadata, DasColumn};
use crate::partial_data_column_sidecar::{
    CellBitmap, DanglingPartialDataColumn, PartialDataColumnSidecar, VerifiablePartialDataColumn,
};
use crate::test_utils::TestRandom;
use crate::{
    BeaconBlockHeader, BeaconStateError, Epoch, EthSpec, ForkName, Hash256,
    SignedBeaconBlockHeader, Slot,
};
use crate::{SignedBeaconBlock, context_deserialize};
use bls::Signature;
use derivative::Derivative;
use kzg::Error as KzgError;
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
use std::borrow::Cow;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type ColumnIndex = u64;
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::BytesPerCell>; // TODO(dknopik): Arc<[u8; E::BytesPerCell]> ??? cell level arcing acors the codebase seems reasonable
pub type DataColumn<E> = VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Identifies a set of data columns associated with a specific beacon block.
#[derive(Encode, Decode, Clone, Debug, PartialEq, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
pub struct DataColumnsByRootIdentifier<E: EthSpec> {
    pub block_root: Hash256,
    pub columns: VariableList<ColumnIndex, E::NumberOfColumns>,
}

pub type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom, Derivative,
)]
#[serde(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[context_deserialize(ForkName)]
pub struct DataColumnSidecar<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: ColumnIndex,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<E>,
    /// All the KZG commitments and proofs associated with the block, used for verifying sample cells.
    pub kzg_commitments: KzgCommitments<E>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    pub signed_block_header: SignedBeaconBlockHeader,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
}

impl<E: EthSpec> DataColumnSidecar<E> {
    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
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

impl<E: EthSpec> DasColumn<E> for DataColumnSidecar<E> {
    fn slot(&self) -> Slot {
        self.slot()
    }

    fn index(&self) -> ColumnIndex {
        self.index
    }

    fn cell_count_total(&self) -> usize {
        self.column.len()
    }

    fn cells_present(&self) -> impl Iterator<Item = usize> {
        0..self.cell_count_total()
    }

    fn column(&self) -> &DataColumn<E> {
        &self.column
    }

    fn kzg_proofs(&self) -> &VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock> {
        &self.kzg_proofs
    }

    fn kzg_commitments(&self) -> &KzgCommitments<E> {
        &self.kzg_commitments
    }

    fn block_root(&self) -> Hash256 {
        self.block_root()
    }

    fn signed_block_header(&self) -> Option<&SignedBeaconBlockHeader> {
        Some(&self.signed_block_header)
    }

    fn into_partial(self) -> VerifiablePartialDataColumn<E> {
        let mut bitmap = CellBitmap::<E>::with_capacity(self.cell_count_total())
            .expect("our column has the same bound");
        for idx in 0..self.cell_count_total() {
            bitmap
                .set(idx, true)
                .expect("The correct size is initialized right above");
        }

        VerifiablePartialDataColumn {
            slot: self.slot(),
            column: Arc::new(DanglingPartialDataColumn {
                block_root: self.block_root(),
                index: self.index(),
                sidecar: PartialDataColumnSidecar {
                    cells_present_bitmap: bitmap,
                    column: self.column,
                    kzg_proofs: self.kzg_proofs,
                },
            }),
            kzg_commitments: self.kzg_commitments,
        }
    }

    fn as_full(
        &self,
        _block: Option<&SignedBeaconBlock<E>>,
    ) -> Option<Cow<'_, DataColumnSidecar<E>>> {
        Some(Cow::Borrowed(self))
    }

    fn iter(&self) -> impl Iterator<Item = Option<CellWithMetadata<'_, E>>> {
        self.column
            .iter()
            .zip(self.kzg_commitments.iter())
            .zip(self.kzg_proofs.iter())
            .map(|((cell, commitment), proof)| {
                Some(CellWithMetadata {
                    cell,
                    commitment,
                    proof,
                })
            })
    }
}
