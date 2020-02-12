use super::{Attestation, EthSpec, PublicKey, Signature};
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A Validators aggregate attestation and proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.10.0
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom, TreeHash)]
#[serde(bound = "T: EthSpec")]
pub struct AggregateAndProof<T: EthSpec> {
    /// The index of the validator that created the attestation.
    pub aggregator_index: u64,
    /// The aggregate attestation.
    pub aggregate: Attestation<T>,
    /// A proof provided by the validator that permits them to publish on the
    /// `beacon_aggregate_and_proof` gossipsub topic.
    pub selection_proof: Signature,
}

impl<T: EthSpec> AggregateAndProof<T> {
    pub fn is_valid_selection_proof(&self, validator_pubkey: &PublicKey) -> bool {
        let message = self.aggregate.data.slot.as_u64().tree_hash_root();
        // FIXME(sproul): remove domain when merging with v0.10 branch
        self.selection_proof.verify(&message, 0, validator_pubkey)
    }
}
