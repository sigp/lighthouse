use crate::core::Spec;
use crate::execution::{ExecutionPayloadGloas, ExecutionRequestsGloas};
use crate::{ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, PartialEq, Hash)]
#[context_deserialize(ForkName)]
#[tree_hash(
    struct_behaviour = "progressive_container",
    active_fields(1, 1, 1, 1, 1)
)]
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayloadGloas,
    // [Modified in Gloas:EIP7688]
    pub execution_requests: ExecutionRequestsGloas,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
}

impl ExecutionPayloadEnvelope {
    /// Returns an empty envelope with all fields zeroed. Used for SSZ size calculations.
    pub fn empty() -> Self {
        Self {
            payload: ExecutionPayloadGloas::default(),
            execution_requests: ExecutionRequestsGloas::default(),
            builder_index: 0,
            beacon_block_root: Hash256::zero(),
            parent_beacon_block_root: Hash256::zero(),
        }
    }

    /// Returns the minimum SSZ-encoded size (all variable-length fields empty).
    pub fn min_size() -> usize {
        Self::empty().as_ssz_bytes().len()
    }

    /// Returns the maximum SSZ-encoded size.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        Self::min_size()
            // ExecutionPayloadGloas variable-length fields:
            + (Spec::MAX_EXTRA_DATA_BYTES * <u8 as SszEncode>::ssz_fixed_len())
            + (Spec::MAX_TRANSACTIONS_PER_PAYLOAD
                * (BYTES_PER_LENGTH_OFFSET + Spec::MAX_BYTES_PER_TRANSACTION))
            + (Spec::MAX_WITHDRAWALS_PER_PAYLOAD
                * <crate::Withdrawal as SszEncode>::ssz_fixed_len())
            // ExecutionRequests variable-length fields:
            + (Spec::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD
                * <crate::DepositRequest as SszEncode>::ssz_fixed_len())
            + (Spec::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
                * <crate::WithdrawalRequest as SszEncode>::ssz_fixed_len())
            + (Spec::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
                * <crate::ConsolidationRequest as SszEncode>::ssz_fixed_len())
    }

    pub fn slot(&self) -> Slot {
        self.payload.slot_number
    }
}

impl SignedRoot for ExecutionPayloadEnvelope {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope);
}
