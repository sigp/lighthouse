use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use BeaconStateError;

#[superstruct(
    variants(Merge, Capella, Eip4844),
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
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        arbitrary(bound = "T: EthSpec")
    ),
    ref_attributes(derive(PartialEq, TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(
    Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec", untagged)]
#[arbitrary(bound = "T: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader<T: EthSpec> {
    #[superstruct(getter(copy))]
    pub parent_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(getter(copy))]
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub base_fee_per_gas: Uint256,
    #[superstruct(only(Eip4844))]
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub excess_data_gas: Uint256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub transactions_root: Hash256,
    #[superstruct(only(Capella, Eip4844))]
    #[superstruct(getter(copy))]
    pub withdrawals_root: Hash256,
}

impl<T: EthSpec> ExecutionPayloadHeader<T> {
    pub fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadHeader: {fork_name}",
            ))),
            ForkName::Merge => ExecutionPayloadHeaderMerge::from_ssz_bytes(bytes).map(Self::Merge),
            ForkName::Capella => {
                ExecutionPayloadHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Eip4844 => {
                ExecutionPayloadHeaderEip4844::from_ssz_bytes(bytes).map(Self::Eip4844)
            }
        }
    }
}

impl<'a, T: EthSpec> ExecutionPayloadHeaderRef<'a, T> {
    pub fn is_default_with_zero_roots(self) -> bool {
        map_execution_payload_header_ref!(&'a _, self, |inner, cons| {
            cons(inner);
            *inner == Default::default()
        })
    }
}

impl<T: EthSpec> ExecutionPayloadHeaderMerge<T> {
    pub fn upgrade_to_capella(&self) -> ExecutionPayloadHeaderCapella<T> {
        ExecutionPayloadHeaderCapella {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: Hash256::zero(),
        }
    }
}

impl<T: EthSpec> ExecutionPayloadHeaderCapella<T> {
    pub fn upgrade_to_eip4844(&self) -> ExecutionPayloadHeaderEip4844<T> {
        ExecutionPayloadHeaderEip4844 {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            // TODO: verify if this is correct
            excess_data_gas: Uint256::zero(),
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
        }
    }
}

impl<'a, T: EthSpec> From<&'a ExecutionPayloadMerge<T>> for ExecutionPayloadHeaderMerge<T> {
    fn from(payload: &'a ExecutionPayloadMerge<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
        }
    }
}
impl<'a, T: EthSpec> From<&'a ExecutionPayloadCapella<T>> for ExecutionPayloadHeaderCapella<T> {
    fn from(payload: &'a ExecutionPayloadCapella<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
        }
    }
}

impl<'a, T: EthSpec> From<&'a ExecutionPayloadEip4844<T>> for ExecutionPayloadHeaderEip4844<T> {
    fn from(payload: &'a ExecutionPayloadEip4844<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            excess_data_gas: payload.excess_data_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
        }
    }
}

// These impls are required to work around an inelegance in `to_execution_payload_header`.
// They only clone headers so they should be relatively cheap.
impl<'a, T: EthSpec> From<&'a Self> for ExecutionPayloadHeaderMerge<T> {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a, T: EthSpec> From<&'a Self> for ExecutionPayloadHeaderCapella<T> {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a, T: EthSpec> From<&'a Self> for ExecutionPayloadHeaderEip4844<T> {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a, T: EthSpec> From<ExecutionPayloadRef<'a, T>> for ExecutionPayloadHeader<T> {
    fn from(payload: ExecutionPayloadRef<'a, T>) -> Self {
        map_execution_payload_ref_into_execution_payload_header!(
            &'a _,
            payload,
            |inner, cons| cons(inner.into())
        )
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for ExecutionPayloadHeaderMerge<T> {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Merge(execution_payload_header) => Ok(execution_payload_header),
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for ExecutionPayloadHeaderCapella<T> {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Capella(execution_payload_header) => {
                Ok(execution_payload_header)
            }
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for ExecutionPayloadHeaderEip4844<T> {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Eip4844(execution_payload_header) => {
                Ok(execution_payload_header)
            }
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}

impl<T: EthSpec> ForkVersionDeserialize for ExecutionPayloadHeader<T> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "ExecutionPayloadHeader failed to deserialize: {:?}",
                e
            ))
        };

        Ok(match fork_name {
            ForkName::Merge => Self::Merge(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Capella => Self::Capella(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Eip4844 => Self::Eip4844(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayloadHeader failed to deserialize: unsupported fork '{}'",
                    fork_name
                )));
            }
        })
    }
}
