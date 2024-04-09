use crate::beacon_block_body::KzgCommitments;
use crate::test_utils::TestRandom;
use crate::BeaconStateError;
use crate::{
    BeaconBlockHeader, BlobSidecarList, EthSpec, Hash256, KzgProofs, SignedBeaconBlock,
    SignedBeaconBlockHeader, Slot,
};
use bls::Signature;
use derivative::Derivative;
use kzg::{Blob as KzgBlob, Error as KzgError, Kzg};
use kzg::{KzgCommitment, KzgProof};
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
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::FieldElementsPerCell>;
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

    pub fn build_sidecars(
        blobs: &BlobSidecarList<E>,
        block: &SignedBeaconBlock<E>,
        kzg: &Kzg,
    ) -> Result<DataColumnSidecarList<E>, DataColumnSidecarError> {
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
            let blob = KzgBlob::from_bytes(&blob.blob).map_err(KzgError::from)?;
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
    use crate::beacon_block::EmptyBlock;
    use crate::beacon_block_body::KzgCommitments;
    use crate::eth_spec::EthSpec;
    use crate::{
        BeaconBlock, BeaconBlockDeneb, Blob, BlobSidecar, BlobSidecarList, ChainSpec,
        DataColumnSidecar, MainnetEthSpec, SignedBeaconBlock,
    };
    use bls::Signature;
    use eth2_network_config::TRUSTED_SETUP_BYTES;
    use kzg::{Kzg, KzgCommitment, KzgProof, TrustedSetup};
    use std::sync::Arc;

    #[test]
    fn test_build_sidecars() {
        type E = MainnetEthSpec;
        let num_of_blobs = 6;
        let spec = E::default_spec();
        let (signed_block, blob_sidecars) =
            create_test_block_and_blob_sidecars::<E>(num_of_blobs, &spec);

        let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP_BYTES).unwrap();
        let kzg = Arc::new(Kzg::new_from_trusted_setup(trusted_setup).unwrap());

        let column_sidecars =
            DataColumnSidecar::build_sidecars(&blob_sidecars, &signed_block, &kzg).unwrap();

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

    fn create_test_block_and_blob_sidecars<E: EthSpec>(
        num_of_blobs: usize,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<E>, BlobSidecarList<E>) {
        let mut block = BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec));
        let mut body = block.body_mut();
        let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
        *blob_kzg_commitments =
            KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs])
                .unwrap();

        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

        let sidecars = (0..num_of_blobs)
            .map(|index| {
                BlobSidecar::new(
                    index,
                    Blob::<E>::default(),
                    &signed_block,
                    KzgProof::empty(),
                )
                .map(Arc::new)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into();

        (signed_block, sidecars)
    }
}
