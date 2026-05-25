use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    core::{Hash256, SignedRoot},
    fork::ForkName,
};

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ForkData {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    pub genesis_validators_root: Hash256,
}

impl SignedRoot for ForkData {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ForkData);
}
