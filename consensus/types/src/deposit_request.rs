use crate::test_utils::TestRandom;
use crate::{Hash256, PublicKeyBytes};
use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct DepositRequest {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

impl DepositRequest {
    pub fn max_size() -> usize {
        Self {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::ZERO,
            amount: 0,
            signature: SignatureBytes::empty(),
            index: 0,
        }
        .as_ssz_bytes()
        .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositRequest);
}
