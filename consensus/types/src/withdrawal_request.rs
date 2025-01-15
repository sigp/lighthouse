use crate::test_utils::TestRandom;
use crate::{Address, PublicKeyBytes};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct WithdrawalRequest {
    #[serde(with = "serde_utils::address_hex")]
    pub source_address: Address,
    pub validator_pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

impl WithdrawalRequest {
    pub fn max_size() -> usize {
        Self {
            source_address: Address::repeat_byte(0),
            validator_pubkey: PublicKeyBytes::empty(),
            amount: 0,
        }
        .as_ssz_bytes()
        .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(WithdrawalRequest);
}
