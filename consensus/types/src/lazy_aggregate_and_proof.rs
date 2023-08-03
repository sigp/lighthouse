use super::{EthSpec, LazyAttestation, Signature};
use crate::{test_utils::TestRandom, AggregateAndProof};
use bls::Error;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A Validators aggregate attestation and selection proof.
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    TreeHash,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LazyAggregateAndProof<T: EthSpec> {
    /// The index of the validator that created the attestation.
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    /// The aggregate attestation.
    pub aggregate: LazyAttestation<T>,
    /// A proof provided by the validator that permits them to publish on the
    /// `beacon_aggregate_and_proof` gossipsub topic.
    pub selection_proof: Signature,
}

impl<T: EthSpec> LazyAggregateAndProof<T> {
    pub fn not_lazy(self) -> Result<AggregateAndProof<T>, Error> {
        Ok(AggregateAndProof {
            aggregator_index: self.aggregator_index,
            aggregate: self.aggregate.to_attestation()?,
            selection_proof: self.selection_proof,
        })
    }
}
