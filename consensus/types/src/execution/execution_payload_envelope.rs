use crate::ForkVersionDecode;
use crate::execution::{ExecutionPayloadGloas, ExecutionRequestsGloas, ExecutionRequestsPq};
use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Pq),
    variant_attributes(
        derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe),
        serde(bound = "E: EthSpec"),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        context_deserialize(ForkName),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec")
        ),
    ),
    specific_variant_attributes(
        Gloas(tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1, 1))),
        Pq(tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1, 1))),
    ),
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    #[superstruct(only(Gloas))]
    pub execution_requests: ExecutionRequestsGloas<E>,
    #[superstruct(only(Pq), partial_getter(rename = "execution_requests_pq"))]
    pub execution_requests: ExecutionRequestsPq<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> ExecutionPayloadEnvelopeGloas<E> {
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
impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelopeGloas<E> {}
impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelopePq<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopeGloas<Spec>);
}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayloadEnvelope<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork {
            ForkName::Pq => ExecutionPayloadEnvelopePq::from_ssz_bytes(bytes).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                ExecutionPayloadEnvelopeGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadEnvelope: {fork}"
            ))),
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayloadEnvelope<E> {
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        fork: ForkName,
    ) -> Result<Self, D::Error> {
        match fork {
            ForkName::Pq => ExecutionPayloadEnvelopePq::deserialize(deserializer).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                ExecutionPayloadEnvelopeGloas::deserialize(deserializer).map(Self::Gloas)
            }
            _ => Err(serde::de::Error::custom(format!(
                "unsupported fork for ExecutionPayloadEnvelope: {fork}"
            ))),
        }
    }
}

#[cfg(test)]
mod pq_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopePq<Spec>);
}
