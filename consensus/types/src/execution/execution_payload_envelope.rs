use crate::consts::gloas::BUILDER_INDEX_SELF_BUILD;
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
    // The builder index is private so that callers are forced to handle the case where it equals
    // BUILDER_INDEX_SELF_BUILD.
    #[serde(with = "serde_utils::quoted_u64")]
    builder_index: u64,
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub blob_kzg_commitments: KzgCommitments<E>,
    pub state_root: Hash256,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    /// Fetch the validator index of the builder of this execution payload.
    ///
    /// This falls back to the provided `proposer_index` if the builder index indicates
    /// self-building.
    pub fn builder_index(&self, proposer_index: u64) -> u64 {
        if self.builder_index == BUILDER_INDEX_SELF_BUILD {
            proposer_index
        } else {
            self.builder_index
        }
    }

    /// Fetch the raw builder index, which may be `BUILDER_INDEX_SELF_BUILD` to indicate
    /// self-building.
    ///
    /// This method should be used sparingly.
    pub fn raw_builder_index(&self) -> u64 {
        self.builder_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope<MainnetEthSpec>);
}
