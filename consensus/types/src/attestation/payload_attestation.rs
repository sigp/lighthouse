use crate::attestation::payload_attestation_data::PayloadAttestationData;
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName};
use bls::AggregateSignature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(TestRandom, TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary", arbitrary(bound = "E: EthSpec"))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
pub struct PayloadAttestation<E: EthSpec> {
    pub aggregation_bits: BitVector<E::PTCSize>,
    pub data: PayloadAttestationData,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod payload_attestation_tests {
    use super::*;
    use crate::MinimalEthSpec;

    ssz_and_tree_hash_tests!(PayloadAttestation<MinimalEthSpec>);
}
