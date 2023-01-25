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
use crate::{Address, EthSpec, ExecutionPayload, Hash256, Hash64, Uint256};
use metastruct::metastruct;

/// Execution block header as used for RLP encoding and Keccak hashing.
///
/// Credit to Reth for the type definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields()))]
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
}

impl ExecutionBlockHeader {
    pub fn from_payload<E: EthSpec>(
        payload: &ExecutionPayload<E>,
        rlp_empty_list_root: Hash256,
        rlp_transactions_root: Hash256,
    ) -> Self {
        // Most of these field mappings are defined in EIP-3675 except for `mixHash`, which is
        // defined in EIP-4399.
        ExecutionBlockHeader {
            parent_hash: payload.parent_hash.into_root(),
            ommers_hash: rlp_empty_list_root,
            beneficiary: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: rlp_transactions_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone().into(),
            difficulty: Uint256::zero(),
            number: payload.block_number.into(),
            gas_limit: payload.gas_limit.into(),
            gas_used: payload.gas_used.into(),
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone().into(),
            mix_hash: payload.prev_randao,
            nonce: Hash64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas,
        }
    }
}
