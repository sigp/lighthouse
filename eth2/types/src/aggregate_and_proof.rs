use super::{Attestation, Domain, EthSpec, Fork, PublicKey, SecretKey, Signature, SignedRoot};
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A Validators aggregate attestation and selection proof.
///
/// Spec v0.10.1
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
    pub fn is_valid_selection_proof(&self, validator_pubkey: &PublicKey, fork: &Fork) -> bool {
        let target_epoch = self.aggregate.data.slot.epoch(T::slots_per_epoch());
        let domain = T::default_spec().get_domain(target_epoch, Domain::SelectionProof, fork);
        let message = self.aggregate.data.slot.signing_root(domain);
        self.selection_proof
            .verify(message.as_bytes(), validator_pubkey)
    }

    /// Converts Self into a SignedAggregateAndProof.
    pub fn into_signed(self, secret_key: &SecretKey, fork: &Fork) -> SignedAggregateAndProof<T> {
        let target_epoch = self.aggregate.data.slot.epoch(T::slots_per_epoch());
        let domain = T::default_spec().get_domain(target_epoch, Domain::AggregateAndProof, fork);
        let sign_message = self.signing_root(domain);
        let signature = Signature::new(sign_message.as_bytes(), &secret_key);

        SignedAggregateAndProof {
            message: self,
            signature,
        }
    }
}

impl<T: EthSpec> SignedRoot for AggregateAndProof<T> {}

/// A Validators signed aggregate proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.10.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom, TreeHash)]
#[serde(bound = "T: EthSpec")]
pub struct SignedAggregateAndProof<T: EthSpec> {
    /// The `AggregateAndProof` that was signed.
    pub message: AggregateAndProof<T>,
    /// The aggregate attestation.
    pub signature: Signature,
}

impl<T: EthSpec> SignedRoot for SignedAggregateAndProof<T> {}

impl<T: EthSpec> SignedAggregateAndProof<T> {
    /// Verifies the signature of the `AggregateAndProof`
    pub fn is_valid_signature(&self, validator_pubkey: &PublicKey, fork: &Fork) -> bool {
        let target_epoch = self.message.aggregate.data.slot.epoch(T::slots_per_epoch());
        let domain = T::default_spec().get_domain(target_epoch, Domain::AggregateAndProof, fork);
        let message = self.signing_root(domain);
        self.signature.verify(message.as_bytes(), validator_pubkey)
    }

    /// Verifies the signature of the `AggregateAndProof` as well the underlying selection_proof in
    /// the contained `AggregateAndProof`.
    pub fn is_valid(&self, validator_pubkey: &PublicKey, fork: &Fork) -> bool {
        self.is_valid_signature(validator_pubkey, fork)
            && self
                .message
                .is_valid_selection_proof(validator_pubkey, fork)
    }
}
