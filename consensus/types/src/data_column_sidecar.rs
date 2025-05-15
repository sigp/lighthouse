use crate::beacon_block_body::{KzgCommitments, BLOB_KZG_COMMITMENTS_INDEX};
use crate::test_utils::TestRandom;
use crate::{
    BeaconBlockHeader, BeaconStateError, Epoch, EthSpec, Hash256, RuntimeVariableList,
    SignedBeaconBlockHeader, Slot,
};
use bls::Signature;
use derivative::Derivative;
use kzg::Error as KzgError;
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::{DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type ColumnIndex = u64;
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::BytesPerCell>;
pub type DataColumn<E> = VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Identifies a set of data columns associated with a specific beacon block.
#[derive(Encode, Clone, Debug, PartialEq)]
pub struct DataColumnsByRootIdentifier {
    pub block_root: Hash256,
    pub columns: RuntimeVariableList<ColumnIndex>,
}

impl RuntimeVariableList<DataColumnsByRootIdentifier> {
    pub fn from_ssz_bytes_with_nested(
        bytes: &[u8],
        max_len: usize,
        num_columns: usize,
    ) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Ok(RuntimeVariableList::empty(max_len));
        }

        let vec = ssz::decode_list_of_variable_length_items::<Vec<u8>, Vec<Vec<u8>>>(
            bytes,
            Some(max_len),
        )?
        .into_iter()
        .map(|bytes| {
            let mut builder = ssz::SszDecoderBuilder::new(&bytes);
            builder.register_type::<Hash256>()?;
            builder.register_anonymous_variable_length_item()?;

            let mut decoder = builder.build()?;
            let block_root = decoder.decode_next()?;
            let columns = decoder.decode_next_with(|bytes| {
                RuntimeVariableList::from_ssz_bytes(bytes, num_columns)
            })?;
            Ok(DataColumnsByRootIdentifier {
                block_root,
                columns,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

        Ok(RuntimeVariableList::from_vec(vec, max_len))
    }
}

pub type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

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
mod test {
    use super::*;
    use bls::FixedBytesExtended;

    #[test]
    fn round_trip_dcbroot_list() {
        let max_outer = 5;
        let max_inner = 10;

        let data = vec![
            DataColumnsByRootIdentifier {
                block_root: Hash256::from_low_u64_be(10),
                columns: RuntimeVariableList::<ColumnIndex>::from_vec(vec![1u64, 2, 3], max_inner),
            },
            DataColumnsByRootIdentifier {
                block_root: Hash256::from_low_u64_be(20),
                columns: RuntimeVariableList::<ColumnIndex>::from_vec(vec![4u64, 5], max_inner),
            },
        ];

        let list = RuntimeVariableList::from_vec(data.clone(), max_outer);

        let ssz_bytes = list.as_ssz_bytes();

        let decoded =
            RuntimeVariableList::<DataColumnsByRootIdentifier>::from_ssz_bytes_with_nested(
                &ssz_bytes, max_outer, max_inner,
            )
            .expect("should decode list of DataColumnsByRootIdentifier");

        assert_eq!(decoded.len(), data.len());
        for (original, decoded) in data.iter().zip(decoded.iter()) {
            assert_eq!(decoded.block_root, original.block_root);
            assert_eq!(
                decoded.columns.iter().copied().collect::<Vec<_>>(),
                original.columns.iter().copied().collect::<Vec<_>>()
            );
        }
    }
}
