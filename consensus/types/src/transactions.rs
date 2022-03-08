use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde::Serialize as Ser;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use std::hash::Hash;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;
pub type BlindedTransactions = Hash256;

pub trait Transactions<T>:
Encode + Decode + TestRandom + TreeHash + Default + PartialEq + Ser + DeserializeOwned + Hash
{
    fn block_type() -> BlockType;
}

impl<T: EthSpec> Transactions<T> for ExecTransactions<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }
}

impl<T: EthSpec> Transactions<T> for BlindedTransactions {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(transparent)]
pub struct ExecTransactions<T: EthSpec>(
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub  VariableList<
        Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
        <T as EthSpec>::MaxTransactionsPerPayload,
    >,
);

impl<T: EthSpec> TreeHash for ExecTransactions<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl<T: EthSpec> TestRandom for ExecTransactions<T> {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        ExecTransactions(<VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TestRandom>::random_for_test(rng))
    }
}

impl<T: EthSpec> Decode for ExecTransactions<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Decode>::from_ssz_bytes(bytes)
            .map(ExecTransactions)
    }
}

impl<T: EthSpec> Encode for ExecTransactions<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}
