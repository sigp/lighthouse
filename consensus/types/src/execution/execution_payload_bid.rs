use crate::kzg_ext::ProgressiveKzgCommitments;
use crate::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash_derive::TreeHash;

#[derive(Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[educe(PartialEq, Hash)]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#executionpayloadbid
#[tree_hash(
    struct_behaviour = "progressive_container",
    active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
)]
pub struct ExecutionPayloadBid<E: EthSpec> {
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
    // [Modified in Gloas:EIP7688]
    pub blob_kzg_commitments: ProgressiveKzgCommitments,
    pub execution_requests_root: Hash256,
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom: PhantomData<E>,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadBid<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBid<MainnetEthSpec>);
}
