use crate::attestation::payload_attestation_data::PayloadAttestationData;
use crate::{ForkName, Spec};
use bls::AggregateSignature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(deny_unknown_fields)]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
pub struct PayloadAttestation {
    pub aggregation_bits: BitVector<typenum::U<{ Spec::PTC_SIZE }>>,
    pub data: PayloadAttestationData,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod payload_attestation_tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestation);
}
