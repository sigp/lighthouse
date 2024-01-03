use crate::beacon_block_body::KzgCommitments;
use crate::test_utils::TestRandom;
use crate::{BlobSidecarList, EthSpec, Hash256, SignedBeaconBlockHeader, Slot};
use derivative::Derivative;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

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
pub struct BlobColumnSidecar<T: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub data: VariableList<u8, T::MaxBytesPerColumn>,
    pub signed_block_header: SignedBeaconBlockHeader,
    /// All of the KZG commitments associated with the block.
    pub kzg_commitments: KzgCommitments<T>,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    pub kzg_commitments_inclusion_proof:
        FixedVector<Hash256, T::AllKzgCommitmentsInclusionProofDepth>,
    // List of cell proofs proving each column sample is part of the extended blob.
    // pub cell_proofs: Vec<CellProof>,
}

impl<T: EthSpec> BlobColumnSidecar<T> {
    pub fn random_from_blob_sidecars(
        blob_sidecars: &BlobSidecarList<T>,
    ) -> Result<Vec<BlobColumnSidecar<T>>, String> {
        if blob_sidecars.is_empty() {
            return Ok(vec![]);
        }

        let first_blob_sidecar = blob_sidecars.first().ok_or("should exist")?;
        let slot = first_blob_sidecar.slot();

        // Proof for kzg commitments in `BeaconBlockBody`
        let body_proof_start = first_blob_sidecar
            .kzg_commitment_inclusion_proof
            .len()
            .saturating_sub(T::all_kzg_commitments_inclusion_proof_depth());
        let kzg_commitments_inclusion_proof: FixedVector<
            Hash256,
            T::AllKzgCommitmentsInclusionProofDepth,
        > = first_blob_sidecar
            .kzg_commitment_inclusion_proof
            .get(body_proof_start..)
            .ok_or("kzg_commitment_inclusion_proof index out of bounds")?
            .to_vec()
            .into();

        let mut rng = StdRng::seed_from_u64(slot.as_u64());
        let num_of_blobs = blob_sidecars.len();
        let bytes_per_column = T::bytes_per_extended_blob() * num_of_blobs / T::blob_column_count();

        (0..T::blob_column_count())
            .map(|col_index| {
                let index = col_index as u64;
                let mut data = vec![0u8; bytes_per_column];
                // Prefix with column index
                let prefix = index.to_le_bytes();
                data.get_mut(..prefix.len())
                    .ok_or("blob column index out of bounds")?
                    .copy_from_slice(&prefix);
                // Fill the rest of the array with random values
                rng.fill(
                    data.get_mut(prefix.len()..)
                        .ok_or("blob column index out of bounds")?,
                );

                Ok(BlobColumnSidecar {
                    index,
                    data: VariableList::new(data).map_err(|e| format!("{e:?}"))?,
                    signed_block_header: first_blob_sidecar.signed_block_header.clone(),
                    kzg_commitments: blob_sidecars
                        .iter()
                        .map(|b| b.kzg_commitment)
                        .collect::<Vec<_>>()
                        .into(),
                    kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }
}

#[cfg(test)]
mod test {
    use crate::beacon_block::EmptyBlock;
    use crate::beacon_block_body::KzgCommitments;
    use crate::eth_spec::EthSpec;
    use crate::{
        BeaconBlock, BeaconBlockDeneb, Blob, BlobColumnSidecar, BlobSidecar, BlobSidecarList,
        ChainSpec, MainnetEthSpec, SignedBeaconBlock,
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

        let column_sidecars = BlobColumnSidecar::random_from_blob_sidecars(&blob_sidecars).unwrap();

        assert_eq!(column_sidecars.len(), E::blob_column_count());

        for (idx, col_sidecar) in column_sidecars.iter().enumerate() {
            assert_eq!(col_sidecar.index, idx as u64);
            assert_eq!(col_sidecar.kzg_commitments.len(), num_of_blobs);
            // ensure column sidecars are prefixed with column index (for verification purpose in prototype only)
            let prefix_len = 8; // column index (u64) is stored as the first 8 bytes
            let col_index_prefix =
                u64::from_le_bytes(col_sidecar.data[0..prefix_len].try_into().unwrap());
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
