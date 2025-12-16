use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName, PayloadAttestationData};
use bls::AggregateSignature;
use context_deserialize::context_deserialize;
use core::slice::Iter;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(TestRandom, TreeHash, Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary", arbitrary(bound = "E: EthSpec"))]
#[context_deserialize(ForkName)]
pub struct IndexedPayloadAttestation<E: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::PTCSize>,
    pub data: PayloadAttestationData,
    pub signature: AggregateSignature,
}

impl<E: EthSpec> IndexedPayloadAttestation<E> {
    pub fn attesting_indices_iter(&self) -> Iter<'_, u64> {
        self.attesting_indices.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(IndexedPayloadAttestation<MainnetEthSpec>);
}
