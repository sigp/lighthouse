use crate::{test_utils::TestRandom, BlobSidecar, EthSpec, Signature};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    TreeHash,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct SignedBlobSidecar<T: EthSpec> {
    pub message: BlobSidecar<T>,
    pub signature: Signature,
}
