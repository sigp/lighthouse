use crate::beacon_block_body::{KzgCommitments, BLOB_KZG_COMMITMENTS_INDEX};
use crate::test_utils::TestRandom;
use crate::{
    BeaconBlockHeader, EthSpec, Hash256, KzgProofs, SignedBeaconBlock, SignedBeaconBlockHeader,
    Slot,
};
use crate::{BeaconStateError, BlobsList};
use bls::Signature;
use derivative::Derivative;
#[cfg_attr(test, double)]
use kzg::Kzg;
use kzg::{Blob as KzgBlob, Error as KzgError};
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
#[cfg(test)]
use mockall_double::double;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
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
    ) -> Result<DataColumnSidecarList<E>, DataColumnSidecarError> {
        if blobs.is_empty() {
            return Ok(DataColumnSidecarList::empty());
        }
        let kzg_commitments = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_err| DataColumnSidecarError::PreDeneb)?;
        let kzg_commitments_inclusion_proof =
            block.message().body().kzg_commitments_merkle_proof()?;
        let signed_block_header = block.signed_block_header();

        let mut columns =
            vec![Vec::with_capacity(E::max_blobs_per_block()); E::number_of_columns()];
        let mut column_kzg_proofs =
            vec![Vec::with_capacity(E::max_blobs_per_block()); E::number_of_columns()];

        // NOTE: assumes blob sidecars are ordered by index
        for blob in blobs {
            let blob = KzgBlob::from_bytes(blob).map_err(KzgError::from)?;
            let (blob_cells, blob_cell_proofs) = kzg.compute_cells_and_proofs(&blob)?;

            // we iterate over each column, and we construct the column from "top to bottom",
            // pushing on the cell and the corresponding proof at each column index. we do this for
            // each blob (i.e. the outer loop).
            for col in 0..E::number_of_columns() {
                let cell =
                    blob_cells
                        .get(col)
                        .ok_or(DataColumnSidecarError::InconsistentArrayLength(format!(
                            "Missing blob cell at index {col}"
                        )))?;
                let cell: Vec<u8> = cell
                    .into_inner()
                    .into_iter()
                    .flat_map(|data| (*data).into_iter())
                    .collect();
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
        let sidecars = DataColumnSidecarList::from(sidecars);

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

pub type DataColumnSidecarList<E> =
    VariableList<Arc<DataColumnSidecar<E>>, <E as EthSpec>::DataColumnCount>;
pub type FixedDataColumnSidecarList<E> =
    FixedVector<Option<Arc<DataColumnSidecar<E>>>, <E as EthSpec>::DataColumnCount>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::beacon_block::EmptyBlock;
    use crate::beacon_block_body::KzgCommitments;
    use crate::eth_spec::EthSpec;
    use crate::{
        BeaconBlock, BeaconBlockDeneb, Blob, ChainSpec, DataColumnSidecar, MainnetEthSpec,
        SignedBeaconBlock,
    };
    use bls::Signature;
    use kzg::KzgCommitment;
    use std::sync::Arc;

    #[test]
    fn test_build_sidecars_empty() {
        type E = MainnetEthSpec;
        let num_of_blobs = 0;
        let spec = E::default_spec();
        let (signed_block, blob_sidecars) = create_test_block_and_blobs::<E>(num_of_blobs, &spec);

        let mock_kzg = Arc::new(Kzg::default());
        let column_sidecars =
            DataColumnSidecar::build_sidecars(&blob_sidecars, &signed_block, &mock_kzg).unwrap();

        assert!(column_sidecars.is_empty());
    }

    #[test]
    fn test_build_sidecars() {
        type E = MainnetEthSpec;
        let num_of_blobs = 6;
        let spec = E::default_spec();
        let (signed_block, blob_sidecars) = create_test_block_and_blobs::<E>(num_of_blobs, &spec);

        let mut mock_kzg = Kzg::default();
        mock_kzg
            .expect_compute_cells_and_proofs()
            .returning(kzg::mock::compute_cells_and_proofs);

        let column_sidecars =
            DataColumnSidecar::build_sidecars(&blob_sidecars, &signed_block, &mock_kzg).unwrap();

        let block_kzg_commitments = signed_block
            .message()
            .body()
            .blob_kzg_commitments()
            .unwrap()
            .clone();
        let block_kzg_commitments_inclusion_proof = signed_block
            .message()
            .body()
            .kzg_commitments_merkle_proof()
            .unwrap();

        assert_eq!(column_sidecars.len(), E::number_of_columns());
        for (idx, col_sidecar) in column_sidecars.iter().enumerate() {
            assert_eq!(col_sidecar.index, idx as u64);

            assert_eq!(col_sidecar.kzg_commitments.len(), num_of_blobs);
            assert_eq!(col_sidecar.column.len(), num_of_blobs);
            assert_eq!(col_sidecar.kzg_proofs.len(), num_of_blobs);

            assert_eq!(col_sidecar.kzg_commitments, block_kzg_commitments);
            assert_eq!(
                col_sidecar.kzg_commitments_inclusion_proof,
                block_kzg_commitments_inclusion_proof
            );
        }
    }

    fn create_test_block_and_blobs<E: EthSpec>(
        num_of_blobs: usize,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<E>, BlobsList<E>) {
        let mut block = BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec));
        let mut body = block.body_mut();
        let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
        *blob_kzg_commitments =
            KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs])
                .unwrap();

        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

        let blobs = (0..num_of_blobs)
            .map(|_| Blob::<E>::default())
            .collect::<Vec<_>>()
            .into();

        (signed_block, blobs)
    }
}
