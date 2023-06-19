use super::{
    Attestation, ChainSpec, Domain, EthSpec, Fork, Hash256, LazyAggregateAndProof, SecretKey,
    SelectionProof, Signature, SignedRoot,
};
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A Validators signed aggregate proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.12.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, arbitrary::Arbitrary)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LazySignedAggregateAndProof<T: EthSpec> {
    /// The  `LazyAggregateAndProof` that was signed.
    pub message: LazyAggregateAndProof<T>,
    /// The aggregate signature
    pub signature: Signature,
}

impl<T: EthSpec> LazySignedAggregateAndProof<T> {}
