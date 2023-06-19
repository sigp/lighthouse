use super::{
    Attestation, ChainSpec, Domain, EthSpec, Fork, Hash256, LazyAttestation, PublicKey, SecretKey,
    SelectionProof, Signature, SignedRoot,
};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A Validators aggregate attestation and selection proof.
///
/// Spec v0.12.1
#[derive(arbitrary::Arbitrary, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LazyAggregateAndProof<T: EthSpec> {
    /// The index of the validator that created the attestation.
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    /// The aggregate lazy attestation
    pub lazy_aggregate: LazyAttestation<T>,
    /// A proof provided by validator
    pub signature: Signature,
}

impl<T: EthSpec> LazyAggregateAndProof<T> {}
