use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

pub enum BlockType {
    Blinded,
    Full,
}

pub trait ExecPayload<T: EthSpec>:
    Encode
    + Decode
    + TestRandom
    + TreeHash
    + Default
    + PartialEq
    + Serialize
    + DeserializeOwned
    + Hash
    + TryFrom<ExecutionPayloadHeader<T>>
    + From<ExecutionPayload<T>>
{
    fn block_type() -> BlockType;

    /// Convert the payload into a payload header.
    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T>;

    // We provide a subset of field accessors, for the fields used in `consensus`.
    //
    // More fields can be added here if you wish.
    fn parent_hash(&self) -> ExecutionBlockHash;
    fn prev_randao(&self) -> Hash256;
    fn timestamp(&self) -> u64;
    fn block_hash(&self) -> ExecutionBlockHash;
}

impl<T: EthSpec> ExecPayload<T> for FullPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::from(&self.execution_payload)
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload.prev_randao
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.block_hash
    }
}

impl<T: EthSpec> ExecPayload<T> for BlindedPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        self.execution_payload_header.clone()
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload_header.prev_randao
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload_header.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.block_hash
    }
}

#[derive(Default, Debug, Clone, TestRandom, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
pub struct BlindedPayload<T: EthSpec> {
    pub execution_payload_header: ExecutionPayloadHeader<T>,
}

impl<T: EthSpec> From<ExecutionPayloadHeader<T>> for BlindedPayload<T> {
    fn from(execution_payload_header: ExecutionPayloadHeader<T>) -> Self {
        Self {
            execution_payload_header,
        }
    }
}

impl<T: EthSpec> From<BlindedPayload<T>> for ExecutionPayloadHeader<T> {
    fn from(blinded: BlindedPayload<T>) -> Self {
        blinded.execution_payload_header
    }
}

impl<T: EthSpec> From<ExecutionPayload<T>> for BlindedPayload<T> {
    fn from(execution_payload: ExecutionPayload<T>) -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeader::from(&execution_payload),
        }
    }
}

impl<T: EthSpec> TreeHash for BlindedPayload<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <ExecutionPayloadHeader<T>>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.execution_payload_header.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <ExecutionPayloadHeader<T>>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.execution_payload_header.tree_hash_root()
    }
}

impl<T: EthSpec> Decode for BlindedPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayloadHeader<T> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <ExecutionPayloadHeader<T> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload_header: ExecutionPayloadHeader::from_ssz_bytes(bytes)?,
        })
    }
}

impl<T: EthSpec> Encode for BlindedPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayloadHeader<T> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.execution_payload_header.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.execution_payload_header.ssz_bytes_len()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, TestRandom, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
pub struct FullPayload<T: EthSpec> {
    pub execution_payload: ExecutionPayload<T>,
}

impl<T: EthSpec> From<ExecutionPayload<T>> for FullPayload<T> {
    fn from(execution_payload: ExecutionPayload<T>) -> Self {
        Self { execution_payload }
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for FullPayload<T> {
    type Error = ();

    fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl<T: EthSpec> TreeHash for FullPayload<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <ExecutionPayload<T>>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.execution_payload.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <ExecutionPayload<T>>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.execution_payload.tree_hash_root()
    }
}

impl<T: EthSpec> Decode for FullPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayload<T> as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(FullPayload {
            execution_payload: Decode::from_ssz_bytes(bytes)?,
        })
    }
}

impl<T: EthSpec> Encode for FullPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayload<T> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.execution_payload.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.execution_payload.ssz_bytes_len()
    }
}
