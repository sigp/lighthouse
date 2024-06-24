use super::{
    AggregateAndProof, AggregateAndProofBase, AggregateAndProofElectra, AggregateAndProofRef,
};
use super::{
    AttestationRef, ChainSpec, Domain, EthSpec, Fork, Hash256, SecretKey, SelectionProof,
    Signature, SignedRoot,
};
use crate::test_utils::TestRandom;
use crate::Attestation;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A Validators signed aggregate proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.12.1
#[superstruct(
    variants(Base, Electra),
    variant_attributes(
        derive(
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
        ),
        serde(bound = "E: EthSpec"),
        arbitrary(bound = "E: EthSpec"),
    ),
    map_into(Attestation),
    map_ref_into(AggregateAndProofRef)
)]
#[derive(
    arbitrary::Arbitrary, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TreeHash,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct SignedAggregateAndProof<E: EthSpec> {
    /// The `AggregateAndProof` that was signed.
    #[superstruct(flatten)]
    pub message: AggregateAndProof<E>,
    /// The aggregate attestation.
    pub signature: Signature,
}

impl<E: EthSpec> SignedAggregateAndProof<E> {
    /// Produces a new `SignedAggregateAndProof` with a `selection_proof` generated by signing
    /// `aggregate.data.slot` with `secret_key`.
    ///
    /// If `selection_proof.is_none()` it will be computed locally.
    pub fn from_aggregate(
        aggregator_index: u64,
        aggregate: AttestationRef<'_, E>,
        selection_proof: Option<SelectionProof>,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let message = AggregateAndProof::from_aggregate(
            aggregator_index,
            aggregate,
            selection_proof,
            secret_key,
            fork,
            genesis_validators_root,
            spec,
        );
        let target_epoch = message.aggregate().data().slot.epoch(E::slots_per_epoch());
        let domain = spec.get_domain(
            target_epoch,
            Domain::AggregateAndProof,
            fork,
            genesis_validators_root,
        );
        let signing_message = message.signing_root(domain);

        Self::from_aggregate_and_proof(message, secret_key.sign(signing_message))
    }

    /// Produces a new `SignedAggregateAndProof` given a `signature` of `aggregate`
    pub fn from_aggregate_and_proof(aggregate: AggregateAndProof<E>, signature: Signature) -> Self {
        match aggregate {
            AggregateAndProof::Base(message) => {
                SignedAggregateAndProof::Base(SignedAggregateAndProofBase { message, signature })
            }
            AggregateAndProof::Electra(message) => {
                SignedAggregateAndProof::Electra(SignedAggregateAndProofElectra {
                    message,
                    signature,
                })
            }
        }
    }

    pub fn message<'a>(&'a self) -> AggregateAndProofRef<'a, E> {
        map_signed_aggregate_and_proof_ref_into_aggregate_and_proof_ref!(
            &'a _,
            self.to_ref(),
            |inner, cons| { cons(&inner.message) }
        )
    }

    pub fn into_attestation(self) -> Attestation<E> {
        map_signed_aggregate_and_proof_into_attestation!(self, |inner, cons| {
            cons(inner.message.aggregate)
        })
    }
}
