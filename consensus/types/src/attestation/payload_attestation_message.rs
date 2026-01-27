use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
#[cfg(feature = "testing")]
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg(feature = "testing")]
use crate::test_utils::TestRandom;
use crate::{ForkName, attestation::PayloadAttestationData};

#[cfg_attr(feature = "testing", derive(TestRandom))]
#[derive(TreeHash, Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub data: PayloadAttestationData,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationMessage);
}
