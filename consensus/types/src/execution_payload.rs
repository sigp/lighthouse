use crate::{test_utils::TestRandom, *};
use safe_arith::{ArithError, SafeArith};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[serde(bound = "T: EthSpec")]
pub struct ExecutionPayload<T: EthSpec> {
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub random: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub base_fee_per_gas: Uint256,
    pub block_hash: Hash256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions:
        VariableList<Transaction<T::MaxBytesPerTransaction>, T::MaxTransactionsPerPayload>,
}

impl<T: EthSpec> ExecutionPayload<T> {
    // TODO: check this whole thing later
    pub fn empty() -> Self {
        Self {
            parent_hash: Hash256::zero(),
            coinbase: Address::default(),
            state_root: Hash256::zero(),
            receipt_root: Hash256::zero(),
            logs_bloom: FixedVector::default(),
            random: Hash256::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: VariableList::empty(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: Hash256::zero(),
            transactions: VariableList::empty(),
        }
    }

    /// Returns the ssz size of `self`.
    pub fn payload_size(&self) -> Result<usize, ArithError> {
        let mut tx_size = ssz::BYTES_PER_LENGTH_OFFSET.safe_mul(self.transactions.len())?;
        for tx in self.transactions.iter() {
            tx_size.safe_add_assign(tx.len())?;
        }
        Self::empty()
            .as_ssz_bytes()
            .len()
            .safe_add(<u8 as Encode>::ssz_fixed_len().safe_mul(self.extra_data.len())?)?
            .safe_add(tx_size)
    }

    #[allow(clippy::integer_arithmetic)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
        // Max size of variable length `extra_data` field
        + (T::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
        // Max size of variable length `transactions` field
        + (T::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + T::max_bytes_per_transaction()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_size() {
        let mut payload = ExecutionPayload::<crate::MainnetEthSpec>::empty();

        assert_eq!(
            payload.as_ssz_bytes().len(),
            payload.payload_size().unwrap()
        );

        payload.extra_data = VariableList::from(vec![42; 16]);
        payload.transactions = VariableList::from(vec![VariableList::from(vec![42; 42])]);

        assert_eq!(
            payload.as_ssz_bytes().len(),
            payload.payload_size().unwrap()
        );
    }
}
