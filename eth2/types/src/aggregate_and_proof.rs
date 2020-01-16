use super::{Attestation, EthSpec, Signature};
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A Validators aggregate attestation and proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.10.0
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom, TreeHash)]
#[serde(bound = "T: EthSpec")]
pub struct AggregateAndProof<T: EthSpec> {
    /// The index of the validator that created the attestation.
    aggregator_index: u64,
    /// The aggregate attestation.
    aggregate: Attestation<T>,
    /// A proof provided by the validator that permits them to publish on the
    /// `beacon_aggregate_and_proof` gossipsub topic.
    selection_proof: Signature,
}
