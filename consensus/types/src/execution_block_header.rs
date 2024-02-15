// Copyright (c) 2022 Reth Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
use crate::{Address, EthSpec, ExecutionPayloadRef, Hash256, Hash64, Uint256};
use alloy_rlp::RlpEncodable;
use metastruct::metastruct;

/// Execution block header as used for RLP encoding and Keccak hashing.
///
/// Credit to Reth for the type definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields_base(exclude(
    withdrawals_root,
    blob_gas_used,
    excess_blob_gas,
    parent_beacon_block_root
)),))]
pub struct ExecutionBlockHeader {
    pub parent_hash: Hash256,
    pub ommers_hash: Hash256,
    pub beneficiary: Address,
    pub state_root: Hash256,
    pub transactions_root: Hash256,
    pub receipts_root: Hash256,
    pub logs_bloom: Vec<u8>,
    pub difficulty: Uint256,
    pub number: Uint256,
    pub gas_limit: Uint256,
    pub gas_used: Uint256,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: Hash256,
    pub nonce: Hash64,
    pub base_fee_per_gas: Uint256,
    pub withdrawals_root: Option<Hash256>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<Hash256>,
}

impl ExecutionBlockHeader {
    pub fn from_payload<E: EthSpec>(
        payload: ExecutionPayloadRef<E>,
        rlp_empty_list_root: Hash256,
        rlp_transactions_root: Hash256,
        rlp_withdrawals_root: Option<Hash256>,
        rlp_blob_gas_used: Option<u64>,
        rlp_excess_blob_gas: Option<u64>,
        rlp_parent_beacon_block_root: Option<Hash256>,
    ) -> Self {
        // Most of these field mappings are defined in EIP-3675 except for `mixHash`, which is
        // defined in EIP-4399.
        ExecutionBlockHeader {
            parent_hash: payload.parent_hash().into_root(),
            ommers_hash: rlp_empty_list_root,
            beneficiary: payload.fee_recipient(),
            state_root: payload.state_root(),
            transactions_root: rlp_transactions_root,
            receipts_root: payload.receipts_root(),
            logs_bloom: payload.logs_bloom().clone().into(),
            difficulty: Uint256::zero(),
            number: payload.block_number().into(),
            gas_limit: payload.gas_limit().into(),
            gas_used: payload.gas_used().into(),
            timestamp: payload.timestamp(),
            extra_data: payload.extra_data().clone().into(),
            mix_hash: payload.prev_randao(),
            nonce: Hash64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas(),
            withdrawals_root: rlp_withdrawals_root,
            blob_gas_used: rlp_blob_gas_used,
            excess_blob_gas: rlp_excess_blob_gas,
            parent_beacon_block_root: rlp_parent_beacon_block_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
#[rlp(trailing)]
pub struct EncodableExecutionBlockHeader<'a> {
    pub parent_hash: &'a [u8],
    pub ommers_hash: &'a [u8],
    pub beneficiary: &'a [u8],
    pub state_root: &'a [u8],
    pub transactions_root: &'a [u8],
    pub receipts_root: &'a [u8],
    pub logs_bloom: &'a [u8],
    pub difficulty: u64,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: &'a [u8],
    pub mix_hash: &'a [u8],
    pub nonce: &'a [u8],
    pub base_fee_per_gas: u64,
    pub withdrawals_root: Option<&'a [u8]>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<&'a [u8]>,
}

impl<'a> From<&'a ExecutionBlockHeader> for EncodableExecutionBlockHeader<'a> {
    fn from(header: &'a ExecutionBlockHeader) -> Self {
        let mut encodable = Self {
            parent_hash: header.parent_hash.as_bytes(),
            ommers_hash: header.ommers_hash.as_bytes(),
            beneficiary: header.beneficiary.as_bytes(),
            state_root: header.state_root.as_bytes(),
            transactions_root: header.transactions_root.as_bytes(),
            receipts_root: header.receipts_root.as_bytes(),
            logs_bloom: header.logs_bloom.as_slice(),
            difficulty: header.difficulty.as_u64(), // TODO this might panic
            number: header.number.as_u64(),         // TODO this might panic
            gas_limit: header.gas_limit.as_u64(),   // TODO this might panic
            gas_used: header.gas_used.as_u64(),     // TODO this might panic
            timestamp: header.timestamp,
            extra_data: header.extra_data.as_slice(),
            mix_hash: header.mix_hash.as_bytes(),
            nonce: header.nonce.as_bytes(),
            base_fee_per_gas: header.base_fee_per_gas.as_u64(), // TODO this might panic
            withdrawals_root: None,
            blob_gas_used: header.blob_gas_used,
            excess_blob_gas: header.excess_blob_gas,
            parent_beacon_block_root: None,
        };
        if let Some(withdrawals_root) = &header.withdrawals_root {
            encodable.withdrawals_root = Some(withdrawals_root.as_bytes());
        }
        if let Some(parent_beacon_block_root) = &header.parent_beacon_block_root {
            encodable.parent_beacon_block_root = Some(parent_beacon_block_root.as_bytes())
        }
        encodable
    }
}
