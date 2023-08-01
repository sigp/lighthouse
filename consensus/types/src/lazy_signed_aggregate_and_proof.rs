use super::{EthSpec, LazyAggregateAndProof, Signature};
use crate::{test_utils::TestRandom, SignedAggregateAndProof};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;
use bls::Error;

/// A Validators signed aggregate proof received from `beacon_aggregate_and_proof`
/// gossipsub topic.
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
pub struct LazySignedAggregateAndProof<T: EthSpec> {
    /// The `LazyAggregateAndProof` that was signed.
    pub message: LazyAggregateAndProof<T>,
    /// The aggregate attestation signature.
    pub signature: Signature,
}

impl<T: EthSpec> LazySignedAggregateAndProof<T> {
    pub fn not_lazy(self) -> Result<SignedAggregateAndProof<T>, Error> {
        Ok(SignedAggregateAndProof {
            message: self.message.not_lazy()?,
            signature: self.signature,
        })
    }
}
