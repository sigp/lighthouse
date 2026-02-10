use crate::test_utils::TestRandom;
use crate::{
    EthSpec, ExecutionPayloadGloas, ExecutionRequests, ForkName, Hash256, KzgCommitments,
    SignedRoot, Slot,
};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TestRandom, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
#[serde(bound = "E: EthSpec")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub blob_kzg_commitments: KzgCommitments<E>,
    pub state_root: Hash256,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope<MainnetEthSpec>);
}
