use crate::execution::{ExecutionPayloadGloas, ExecutionRequests};
use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
#[serde(bound = "E: EthSpec")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    /// Returns an empty envelope with all fields zeroed. Used for SSZ size calculations.
    pub fn empty() -> Self {
        Self {
            payload: ExecutionPayloadGloas::default(),
            execution_requests: ExecutionRequests::default(),
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
            + (E::max_extra_data_bytes() * <u8 as SszEncode>::ssz_fixed_len())
            + (E::max_transactions_per_payload()
                * (BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            + (E::max_withdrawals_per_payload()
                * <crate::Withdrawal as SszEncode>::ssz_fixed_len())
            // ExecutionRequests variable-length fields:
            + (E::max_deposit_requests_per_payload()
                * <crate::DepositRequest as SszEncode>::ssz_fixed_len())
            + (E::max_withdrawal_requests_per_payload()
                * <crate::WithdrawalRequest as SszEncode>::ssz_fixed_len())
            + (E::max_consolidation_requests_per_payload()
                * <crate::ConsolidationRequest as SszEncode>::ssz_fixed_len())
    }

    pub fn slot(&self) -> Slot {
        self.payload.slot_number
    }
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope<MainnetEthSpec>);
}
