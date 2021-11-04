use crate::{test_utils::TestRandom, *};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound = "T: EthSpec")]
pub struct Transaction<T: EthSpec>(
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    VariableList<u8, T::MaxBytesPerTransaction>,
);

impl<T: EthSpec> Transaction<T> {
    pub fn new(tx: VariableList<u8, T::MaxBytesPerTransaction>) -> Transaction<T> {
        Self(tx)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<T: EthSpec> Encode for Transaction<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<u8, T::MaxBytesPerTransaction> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_fixed_len() -> usize {
        <VariableList<u8, T::MaxBytesPerTransaction> as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}

impl<T: EthSpec> Decode for Transaction<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<u8, T::MaxBytesPerTransaction> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <VariableList<u8, T::MaxBytesPerTransaction> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Transaction(VariableList::from_ssz_bytes(bytes)?))
    }
}

impl<T: EthSpec> tree_hash::TreeHash for Transaction<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl<T: EthSpec> SignedRoot for Transaction<T> {}

impl<T: EthSpec> TestRandom for Transaction<T> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        Transaction(VariableList::random_for_test(rng))
    }
}

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
    pub base_fee_per_gas: Hash256,
    pub block_hash: Hash256,
    #[test_random(default)]
    pub transactions: VariableList<Transaction<T>, T::MaxTransactionsPerPayload>,
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
            base_fee_per_gas: Hash256::zero(),
            block_hash: Hash256::zero(),
            transactions: VariableList::empty(),
        }
    }
}
