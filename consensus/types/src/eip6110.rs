use crate::test_utils::TestRandom;
use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    // PartialEq,
    // Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct DepositReceipt {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
}

// Manually implement the Eq trait for DepositReceipt
impl Eq for DepositReceipt {}

impl PartialEq<DepositReceipt> for DepositReceipt {
    fn eq(&self, other: &DepositReceipt) -> bool {
        self.pubkey == other.pubkey
            && self.withdrawal_credentials == other.withdrawal_credentials
            && self.amount == other.amount
            && self.index == other.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositReceipt);
}
