use crate::{Address, ForkName};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
pub struct BuilderPendingWithdrawal {
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderPendingWithdrawal);
}
