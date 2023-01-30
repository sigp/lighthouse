use crate::test_utils::TestRandom;
use crate::{Blob, EthSpec, Hash256, SignedRoot, Slot};
use derivative::Derivative;
use kzg::KzgProof;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub struct BlobsSidecar<T: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: VariableList<Blob<T>, T::MaxBlobsPerBlock>,
    pub kzg_aggregated_proof: KzgProof,
}

impl<T: EthSpec> SignedRoot for BlobsSidecar<T> {}

impl<T: EthSpec> BlobsSidecar<T> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn empty_from_parts(beacon_block_root: Hash256, beacon_block_slot: Slot) -> Self {
        Self {
            beacon_block_root,
            beacon_block_slot,
            blobs: VariableList::empty(),
            kzg_aggregated_proof: KzgProof::empty(),
        }
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
            // Max size of variable length `blobs` field
            + (T::max_blobs_per_block() * <Blob<T> as Encode>::ssz_fixed_len())
    }
}
