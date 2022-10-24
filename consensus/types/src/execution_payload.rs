use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::slice::Iter;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type Transaction<N> = VariableList<u8, N>;
pub type Transactions<T> = VariableList<
    Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
    <T as EthSpec>::MaxTransactionsPerPayload,
>;

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
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct ExecutionPayload<T: EthSpec> {
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
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<T>,
    #[superstruct(only(Capella, Eip4844))]
    pub withdrawals: VariableList<Withdrawal, T::MaxWithdrawalsPerPayload>,
}

impl<T: EthSpec> ExecutionPayload<T> {
    #[allow(clippy::integer_arithmetic)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_merge_size() -> usize {
        // Fixed part
        ExecutionPayloadMerge::<T>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (T::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (T::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + T::max_bytes_per_transaction()))
    }

    #[allow(clippy::integer_arithmetic)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_capella_size() -> usize {
        // Fixed part
        ExecutionPayloadCapella::<T>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (T::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (T::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + T::max_bytes_per_transaction()))
            // Max size of variable length `withdrawals` field
            + (T::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }

    #[allow(clippy::integer_arithmetic)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_eip4844_size() -> usize {
        // Fixed part
        ExecutionPayloadEip4844::<T>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (T::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (T::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + T::max_bytes_per_transaction()))
            // Max size of variable length `withdrawals` field
            + (T::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }

    pub fn blob_txns_iter(&self) -> Iter<'_, Transaction<T::MaxBytesPerTransaction>> {
        self.transactions().iter()
    }
}
