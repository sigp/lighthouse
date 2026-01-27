use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
#[cfg(feature = "testing")]
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg(feature = "testing")]
use crate::test_utils::TestRandom;
use crate::{
    core::{Hash256, SignedRoot},
    fork::ForkName,
};

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "testing", derive(TestRandom))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct DepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

impl SignedRoot for DepositMessage {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositMessage);
}
