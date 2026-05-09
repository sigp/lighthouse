use crate::execution::{
    ExecutionPayloadGloas, ExecutionPayloadHeze, ExecutionPayloadRef, ExecutionRequests,
};
use crate::fork::ForkVersionDecode;
use crate::state::BeaconStateError;
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
        context_deserialize(ForkName),
    ),
    ref_attributes(
        derive(PartialEq, TreeHash, Debug),
        tree_hash(enum_behaviour = "transparent")
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    #[superstruct(only(Gloas), partial_getter(rename = "payload_gloas"))]
    pub payload: ExecutionPayloadGloas<E>,
    #[superstruct(only(Heze), partial_getter(rename = "payload_heze"))]
    pub payload: ExecutionPayloadHeze<E>,
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub builder_index: u64,
    #[superstruct(getter(copy))]
    pub beacon_block_root: Hash256,
    #[superstruct(getter(copy))]
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    pub fn slot(&self) -> Slot {
        match self {
            Self::Gloas(env) => env.payload.slot_number,
            Self::Heze(env) => env.payload.slot_number,
        }
    }

    pub fn payload(&self) -> ExecutionPayloadRef<'_, E> {
        match self {
            Self::Gloas(env) => ExecutionPayloadRef::Gloas(&env.payload),
            Self::Heze(env) => ExecutionPayloadRef::Heze(&env.payload),
        }
    }
}

impl<'a, E: EthSpec> ExecutionPayloadEnvelopeRef<'a, E> {
    pub fn slot(&self) -> Slot {
        match self {
            Self::Gloas(env) => env.payload.slot_number,
            Self::Heze(env) => env.payload.slot_number,
        }
    }

    pub fn payload(&self) -> ExecutionPayloadRef<'_, E> {
        match self {
            Self::Gloas(env) => ExecutionPayloadRef::Gloas(&env.payload),
            Self::Heze(env) => ExecutionPayloadRef::Heze(&env.payload),
        }
    }
}

impl<E: EthSpec> ExecutionPayloadEnvelopeGloas<E> {
    pub fn empty() -> Self {
        Self {
            payload: ExecutionPayloadGloas::default(),
            execution_requests: ExecutionRequests::default(),
            builder_index: 0,
            beacon_block_root: Hash256::ZERO,
            parent_beacon_block_root: Hash256::ZERO,
        }
    }

    pub fn min_size() -> usize {
        Self::empty().as_ssz_bytes().len()
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        Self::min_size()
            + (E::max_extra_data_bytes() * <u8 as SszEncode>::ssz_fixed_len())
            + (E::max_transactions_per_payload()
                * (BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            + (E::max_withdrawals_per_payload() * <crate::Withdrawal as SszEncode>::ssz_fixed_len())
            + (E::max_deposit_requests_per_payload()
                * <crate::DepositRequest as SszEncode>::ssz_fixed_len())
            + (E::max_withdrawal_requests_per_payload()
                * <crate::WithdrawalRequest as SszEncode>::ssz_fixed_len())
            + (E::max_consolidation_requests_per_payload()
                * <crate::ConsolidationRequest as SszEncode>::ssz_fixed_len())
    }
}

impl<E: EthSpec> ExecutionPayloadEnvelopeHeze<E> {
    pub fn empty() -> Self {
        Self {
            payload: ExecutionPayloadHeze::default(),
            execution_requests: ExecutionRequests::default(),
            builder_index: 0,
            beacon_block_root: Hash256::ZERO,
            parent_beacon_block_root: Hash256::ZERO,
        }
    }

    pub fn min_size() -> usize {
        Self::empty().as_ssz_bytes().len()
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        Self::min_size()
            + (E::max_extra_data_bytes() * <u8 as SszEncode>::ssz_fixed_len())
            + (E::max_transactions_per_payload()
                * (BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            + (E::max_withdrawals_per_payload() * <crate::Withdrawal as SszEncode>::ssz_fixed_len())
            + (E::max_deposit_requests_per_payload()
                * <crate::DepositRequest as SszEncode>::ssz_fixed_len())
            + (E::max_withdrawal_requests_per_payload()
                * <crate::WithdrawalRequest as SszEncode>::ssz_fixed_len())
            + (E::max_consolidation_requests_per_payload()
                * <crate::ConsolidationRequest as SszEncode>::ssz_fixed_len())
    }
}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayloadEnvelope<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Gloas => {
                <ExecutionPayloadEnvelopeGloas<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Gloas)
            }
            ForkName::Heze => {
                <ExecutionPayloadEnvelopeHeze<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Heze)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadEnvelope: {fork_name}",
            ))),
        }
    }
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}
impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelopeGloas<E> {}
impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelopeHeze<E> {}
impl<'a, E: EthSpec> SignedRoot for ExecutionPayloadEnvelopeRef<'a, E> {}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayloadEnvelope<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "ExecutionPayloadEnvelope failed to deserialize: {:?}",
                e
            ))
        };
        match context {
            ForkName::Heze => Ok(Self::Heze(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            ForkName::Gloas => Ok(Self::Gloas(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            _ => Err(serde::de::Error::custom(format!(
                "ExecutionPayloadEnvelope failed to deserialize: unsupported fork '{}'",
                context
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    mod gloas {
        use super::*;
        ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopeGloas<MainnetEthSpec>);
    }
    mod heze {
        use super::*;
        ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopeHeze<MainnetEthSpec>);
    }
}
