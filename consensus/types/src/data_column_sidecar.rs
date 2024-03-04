use crate::beacon_block_body::KzgCommitments;
use crate::test_utils::TestRandom;
use crate::{
    BeaconBlockHeader, BlobSidecarList, EthSpec, Hash256, KzgProofs, SignedBeaconBlockHeader, Slot,
};
use bls::Signature;
use derivative::Derivative;
use kzg::{KzgCommitment, KzgProof};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
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
pub type Cell<T> = FixedVector<u8, <T as EthSpec>::FieldElementsPerCell>;
pub type DataColumn<T> = VariableList<Cell<T>, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;

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
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "T: EthSpec"))]
pub struct DataColumnSidecar<T: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: ColumnIndex,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<T>,
    /// All of the KZG commitments and proofs associated with the block, used for verifying sample cells.
    pub kzg_commitments: KzgCommitments<T>,
    pub kzg_proofs: KzgProofs<T>,
    pub signed_block_header: SignedBeaconBlockHeader,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, T::KzgCommitmentsInclusionProofDepth>,
}

impl<T: EthSpec> DataColumnSidecar<T> {
    pub fn random_from_blob_sidecars(
        blob_sidecars: &BlobSidecarList<T>,
    ) -> Result<Vec<DataColumnSidecar<T>>, DataColumnSidecarError> {
        if blob_sidecars.is_empty() {
            return Ok(vec![]);
        }

        let first_blob_sidecar = blob_sidecars
            .first()
            .ok_or(DataColumnSidecarError::MissingBlobSidecars)?;
        let slot = first_blob_sidecar.slot();

        // Proof for kzg commitments in `BeaconBlockBody`
        let body_proof_start = first_blob_sidecar
            .kzg_commitment_inclusion_proof
            .len()
            .saturating_sub(T::kzg_commitments_inclusion_proof_depth());
        let kzg_commitments_inclusion_proof: FixedVector<
            Hash256,
            T::KzgCommitmentsInclusionProofDepth,
        > = first_blob_sidecar
            .kzg_commitment_inclusion_proof
            .get(body_proof_start..)
            .ok_or(DataColumnSidecarError::KzgCommitmentInclusionProofOutOfBounds)?
            .to_vec()
            .into();

        let mut rng = StdRng::seed_from_u64(slot.as_u64());
        let num_of_blobs = blob_sidecars.len();

        (0..T::number_of_columns())
            .map(|col_index| {
                Ok(DataColumnSidecar {
                    index: col_index as u64,
                    column: Self::generate_column_data(&mut rng, num_of_blobs, col_index)?,
                    kzg_commitments: blob_sidecars
                        .iter()
                        .map(|b| b.kzg_commitment)
                        .collect::<Vec<_>>()
                        .into(),
                    kzg_proofs: blob_sidecars
                        .iter()
                        .map(|b| b.kzg_proof)
                        .collect::<Vec<_>>()
                        .into(),
                    signed_block_header: first_blob_sidecar.signed_block_header.clone(),
                    kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn generate_column_data(
        rng: &mut StdRng,
        num_of_blobs: usize,
        index: usize,
    ) -> Result<DataColumn<T>, DataColumnSidecarError> {
        let mut dummy_cell_data = Cell::<T>::default();
        // Prefix with column index
        let prefix = index.to_le_bytes();
        dummy_cell_data
            .get_mut(..prefix.len())
            .ok_or(DataColumnSidecarError::DataColumnIndexOutOfBounds)?
            .copy_from_slice(&prefix);
        // Fill the rest of the vec with random values
        rng.fill(
            dummy_cell_data
                .get_mut(prefix.len()..)
                .ok_or(DataColumnSidecarError::DataColumnIndexOutOfBounds)?,
        );

        let column = DataColumn::<T>::new(vec![dummy_cell_data; num_of_blobs])?;
        Ok(column)
    }

    pub fn id(&self) -> DataColumnIdentifier {
        DataColumnIdentifier {
            block_root: self.block_root(),
            index: self.index,
        }
    }

    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }

    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<T>::default()]).unwrap(),
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
            column: VariableList::new(vec![Cell::<T>::default(); T::MaxBlobsPerBlock::to_usize()])
                .unwrap(),
            kzg_commitments: VariableList::new(vec![
                KzgCommitment::empty_for_testing();
                T::MaxBlobsPerBlock::to_usize()
            ])
            .unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); T::MaxBlobsPerBlock::to_usize()])
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
    MissingBlobSidecars,
    KzgCommitmentInclusionProofOutOfBounds,
    DataColumnIndexOutOfBounds,
    SszError(SszError),
}

impl From<ArithError> for DataColumnSidecarError {
    fn from(e: ArithError) -> Self {
        Self::ArithError(e)
    }
}

impl From<SszError> for DataColumnSidecarError {
    fn from(e: SszError) -> Self {
        Self::SszError(e)
    }
}

pub type DataColumnSidecarList<T> =
    VariableList<Arc<DataColumnSidecar<T>>, <T as EthSpec>::DataColumnCount>;
pub type FixedDataColumnSidecarList<T> =
    FixedVector<Option<Arc<DataColumnSidecar<T>>>, <T as EthSpec>::DataColumnCount>;

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
    use kzg::{KzgCommitment, KzgProof};
    use std::sync::Arc;

    #[test]
    fn test_random_from_blob_sidecars() {
        type E = MainnetEthSpec;
        let num_of_blobs = 6;
        let spec = E::default_spec();
        let blob_sidecars: BlobSidecarList<E> = create_test_blob_sidecars(num_of_blobs, &spec);

        let column_sidecars = DataColumnSidecar::random_from_blob_sidecars(&blob_sidecars).unwrap();

        assert_eq!(column_sidecars.len(), E::number_of_columns());

        for (idx, col_sidecar) in column_sidecars.iter().enumerate() {
            assert_eq!(col_sidecar.index, idx as u64);
            assert_eq!(col_sidecar.kzg_commitments.len(), num_of_blobs);
            // ensure column sidecars are prefixed with column index (for verification purpose in prototype only)
            let prefix_len = 8; // column index (u64) is stored as the first 8 bytes
            let cell = col_sidecar.column.first().unwrap();
            let col_index_prefix = u64::from_le_bytes(cell[0..prefix_len].try_into().unwrap());
            assert_eq!(col_index_prefix, idx as u64)
        }
    }

    fn create_test_blob_sidecars<E: EthSpec>(
        num_of_blobs: usize,
        spec: &ChainSpec,
    ) -> BlobSidecarList<E> {
        let mut block = BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec));
        let mut body = block.body_mut();
        let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
        *blob_kzg_commitments =
            KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs])
                .unwrap();

        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

        (0..num_of_blobs)
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
            .into()
    }
}
