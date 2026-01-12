use crate::test_utils::TestRandom;
use crate::{Address, ExecutionBlockHash, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe, TestRandom,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#executionpayloadbid
pub struct ExecutionPayloadBid {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Hash256,
    pub block_hash: ExecutionBlockHash,
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub value: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub execution_payment: u64,
    pub blob_kzg_commitments_root: Hash256,
}

impl SignedRoot for ExecutionPayloadBid {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ExecutionPayloadBid);
}
