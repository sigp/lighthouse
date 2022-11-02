use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
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
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    ref_attributes(derive(PartialEq, TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
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
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub excess_blobs: u64,
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
}

impl<'a, T: EthSpec> ExecutionPayloadHeaderRef<'a, T> {
    // FIXME: maybe this could be a derived trait..
    pub fn is_default(self) -> bool {
        match self {
            ExecutionPayloadHeaderRef::Merge(header) => {
                *header == ExecutionPayloadHeaderMerge::default()
            }
            ExecutionPayloadHeaderRef::Capella(header) => {
                *header == ExecutionPayloadHeaderCapella::default()
            }
            ExecutionPayloadHeaderRef::Eip4844(header) => {
                *header == ExecutionPayloadHeaderEip4844::default()
            }
        }
    }
}

impl<T: EthSpec> ExecutionPayloadHeaderMerge<T> {
    pub fn upgrade_to_capella(&self) -> ExecutionPayloadHeaderCapella<T> {
        // TODO: if this is correct we should calculate and hardcode this..
        let empty_withdrawals_root =
            VariableList::<Withdrawal, T::MaxWithdrawalsPerPayload>::empty().tree_hash_root();
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
            // FIXME: the spec doesn't seem to define what to do here..
            withdrawals_root: empty_withdrawals_root,
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
            excess_blobs: 0,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
        }
    }
}

impl<T: EthSpec> From<ExecutionPayloadMerge<T>> for ExecutionPayloadHeaderMerge<T> {
    fn from(payload: ExecutionPayloadMerge<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadCapella<T>> for ExecutionPayloadHeaderCapella<T> {
    fn from(payload: ExecutionPayloadCapella<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadEip4844<T>> for ExecutionPayloadHeaderEip4844<T> {
    fn from(payload: ExecutionPayloadEip4844<T>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            excess_blobs: payload.excess_blobs,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
        }
    }
}

impl<T: EthSpec> From<ExecutionPayloadMerge<T>> for ExecutionPayloadHeader<T> {
    fn from(payload: ExecutionPayloadMerge<T>) -> Self {
        Self::Merge(ExecutionPayloadHeaderMerge::from(payload))
    }
}

impl<T: EthSpec> From<ExecutionPayloadCapella<T>> for ExecutionPayloadHeader<T> {
    fn from(payload: ExecutionPayloadCapella<T>) -> Self {
        Self::Capella(ExecutionPayloadHeaderCapella::from(payload))
    }
}

impl<T: EthSpec> From<ExecutionPayloadEip4844<T>> for ExecutionPayloadHeader<T> {
    fn from(payload: ExecutionPayloadEip4844<T>) -> Self {
        Self::Eip4844(ExecutionPayloadHeaderEip4844::from(payload))
    }
}

impl<T: EthSpec> From<ExecutionPayload<T>> for ExecutionPayloadHeader<T> {
    fn from(payload: ExecutionPayload<T>) -> Self {
        match payload {
            ExecutionPayload::Merge(payload) => Self::from(payload),
            ExecutionPayload::Capella(payload) => Self::from(payload),
            ExecutionPayload::Eip4844(payload) => Self::from(payload),
        }
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
