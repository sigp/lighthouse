use crate::test_utils::TestRandom;
use crate::{BlobSidecar, ChainSpec, EthSpec, Fork, Hash256, PublicKey, Signature, SignedRoot};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
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
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub struct SignedBlobSidecar<T: EthSpec> {
    pub message: BlobSidecar<T>,
    pub signature: Signature,
}

impl<T: EthSpec> SignedRoot for SignedBlobSidecar<T> {}

impl<T: EthSpec> SignedBlobSidecar<T> {
    pub fn verify_signature(
        &self,
        _object_root_opt: Option<Hash256>,
        _pubkey: &PublicKey,
        _fork: &Fork,
        _genesis_validators_root: Hash256,
        _spec: &ChainSpec,
    ) -> bool {
        // TODO (pawan): fill up logic
        unimplemented!()
    }
}
