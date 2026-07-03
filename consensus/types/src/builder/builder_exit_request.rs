use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{core::Address, fork::ForkName};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct BuilderExitRequest {
    #[serde(with = "serde_utils::address_hex")]
    pub source_address: Address,
    pub pubkey: PublicKeyBytes,
}

impl BuilderExitRequest {
    pub fn max_size() -> usize {
        Self {
            source_address: Address::repeat_byte(0),
            pubkey: PublicKeyBytes::empty(),
        }
        .as_ssz_bytes()
        .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderExitRequest);
}
