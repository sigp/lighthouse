use crate::{Address, EthSpec, ExecutionPayload, Hash256, Hash64, Uint256};
use metastruct::metastruct;

// Copied from `reth` :)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields()))]
pub struct ExecutionBlockHeader {
    /// The Keccak 256-bit hash of the parent
    /// block’s header, in its entirety; formally Hp.
    pub parent_hash: Hash256,
    /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
    pub ommers_hash: Hash256,
    /// The 160-bit address to which all fees collected from the successful mining of this block
    /// be transferred; formally Hc.
    pub beneficiary: Address,
    /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
    /// executed and finalisations applied; formally Hr.
    pub state_root: Hash256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// transaction in the transactions list portion of the
    /// block; formally Ht.
    pub transactions_root: Hash256,
    /// The Keccak 256-bit hash of the root
    /// node of the trie structure populated with the receipts of each transaction in the
    /// transactions list portion of the block; formally He.
    pub receipts_root: Hash256,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
    pub logs_bloom: Vec<u8>,
    /// A scalar value corresponding to the difficulty level of this block. This can be calculated
    /// from the previous block’s difficulty level and the timestamp; formally Hd.
    pub difficulty: Uint256,
    /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
    /// zero; formally Hi.
    pub number: Uint256,
    /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
    pub gas_limit: Uint256,
    /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
    pub gas_used: Uint256,
    /// A scalar value equal to the reasonable output of Unix’s time() at this block’s inception;
    /// formally Hs.
    pub timestamp: u64,
    /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
    /// fewer; formally Hx.
    pub extra_data: Vec<u8>,
    /// A 256-bit hash which, combined with the
    /// nonce, proves that a sufficient amount of computation has been carried out on this block;
    /// formally Hm.
    pub mix_hash: Hash256,
    /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block; formally Hn.
    pub nonce: Hash64,
    /// A scalar representing EIP1559 base fee which can move up or down each block according
    /// to a formula which is a function of gas used in parent block and gas target
    /// (block gas limit divided by elasticity multiplier) of parent block.
    /// The algorithm results in the base fee per gas increasing when blocks are
    /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
    /// gas is burned.
    pub base_fee_per_gas: Uint256,
}

impl ExecutionBlockHeader {
    pub fn from_payload<E: EthSpec>(
        payload: &ExecutionPayload<E>,
        rlp_empty_list_root: Hash256,
        rlp_transactions_root: Hash256,
    ) -> Self {
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
            mix_hash: Hash256::zero(),
            nonce: Hash64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas,
        }
    }
}
