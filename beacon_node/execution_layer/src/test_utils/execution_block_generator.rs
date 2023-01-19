use crate::engines::ForkchoiceState;
use crate::{
    engine_api::{
        json_structures::{
            JsonForkchoiceUpdatedV1Response, JsonPayloadStatusV1, JsonPayloadStatusV1Status,
        },
        ExecutionBlock, PayloadAttributes, PayloadId, PayloadStatusV1, PayloadStatusV1Status,
    },
    ExecutionBlockWithTransactions,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::{
    EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadCapella,
    ExecutionPayloadEip4844, ExecutionPayloadMerge, ForkName, Hash256, Uint256,
};

const GAS_LIMIT: u64 = 16384;
const GAS_USED: u64 = GAS_LIMIT - 1;

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)] // This struct is only for testing.
pub enum Block<T: EthSpec> {
    PoW(PoWBlock),
    PoS(ExecutionPayload<T>),
}

impl<T: EthSpec> Block<T> {
    pub fn block_number(&self) -> u64 {
        match self {
            Block::PoW(block) => block.block_number,
            Block::PoS(payload) => payload.block_number(),
        }
    }

    pub fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Block::PoW(block) => block.parent_hash,
            Block::PoS(payload) => payload.parent_hash(),
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Block::PoW(block) => block.block_hash,
            Block::PoS(payload) => payload.block_hash(),
        }
    }

    pub fn total_difficulty(&self) -> Option<Uint256> {
        match self {
            Block::PoW(block) => Some(block.total_difficulty),
            Block::PoS(_) => None,
        }
    }

    pub fn as_execution_block(&self, total_difficulty: Uint256) -> ExecutionBlock {
        match self {
            Block::PoW(block) => ExecutionBlock {
                block_hash: block.block_hash,
                block_number: block.block_number,
                parent_hash: block.parent_hash,
                total_difficulty: block.total_difficulty,
                timestamp: block.timestamp,
            },
            Block::PoS(payload) => ExecutionBlock {
                block_hash: payload.block_hash(),
                block_number: payload.block_number(),
                parent_hash: payload.parent_hash(),
                total_difficulty,
                timestamp: payload.timestamp(),
            },
        }
    }

    pub fn as_execution_block_with_tx(&self) -> Option<ExecutionBlockWithTransactions<T>> {
        match self {
            Block::PoS(payload) => Some(payload.clone().try_into().unwrap()),
            Block::PoW(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct PoWBlock {
    pub block_number: u64,
    pub block_hash: ExecutionBlockHash,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ExecutionBlockGenerator<T: EthSpec> {
    /*
     * Common database
     */
    head_block: Option<Block<T>>,
    finalized_block_hash: Option<ExecutionBlockHash>,
    blocks: HashMap<ExecutionBlockHash, Block<T>>,
    block_hashes: HashMap<u64, Vec<ExecutionBlockHash>>,
    /*
     * PoW block parameters
     */
    pub terminal_total_difficulty: Uint256,
    pub terminal_block_number: u64,
    pub terminal_block_hash: ExecutionBlockHash,
    /*
     * PoS block parameters
     */
    pub pending_payloads: HashMap<ExecutionBlockHash, ExecutionPayload<T>>,
    pub next_payload_id: u64,
    pub payload_ids: HashMap<PayloadId, ExecutionPayload<T>>,
    /*
     * Post-merge fork triggers
     */
    pub shanghai_time: Option<u64>, // withdrawals
    pub eip4844_time: Option<u64>,  // 4844
}

impl<T: EthSpec> ExecutionBlockGenerator<T> {
    pub fn new(
        terminal_total_difficulty: Uint256,
        terminal_block_number: u64,
        terminal_block_hash: ExecutionBlockHash,
        shanghai_time: Option<u64>,
        eip4844_time: Option<u64>,
    ) -> Self {
        let mut gen = Self {
            head_block: <_>::default(),
            finalized_block_hash: <_>::default(),
            blocks: <_>::default(),
            block_hashes: <_>::default(),
            terminal_total_difficulty,
            terminal_block_number,
            terminal_block_hash,
            pending_payloads: <_>::default(),
            next_payload_id: 0,
            payload_ids: <_>::default(),
            shanghai_time,
            eip4844_time,
        };

        gen.insert_pow_block(0).unwrap();

        gen
    }

    pub fn latest_block(&self) -> Option<Block<T>> {
        self.head_block.clone()
    }

    pub fn latest_execution_block(&self) -> Option<ExecutionBlock> {
        self.latest_block()
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
    }

    pub fn block_by_number(&self, number: u64) -> Option<Block<T>> {
        // Get the latest canonical head block
        let mut latest_block = self.latest_block()?;
        loop {
            let block_number = latest_block.block_number();
            if block_number < number {
                return None;
            }
            if block_number == number {
                return Some(latest_block);
            }
            latest_block = self.block_by_hash(latest_block.parent_hash())?;
        }
    }

    pub fn get_fork_at_timestamp(&self, timestamp: u64) -> ForkName {
        match self.eip4844_time {
            Some(fork_time) if timestamp >= fork_time => ForkName::Eip4844,
            _ => match self.shanghai_time {
                Some(fork_time) if timestamp >= fork_time => ForkName::Capella,
                _ => ForkName::Merge,
            },
        }
    }

    pub fn execution_block_by_number(&self, number: u64) -> Option<ExecutionBlock> {
        self.block_by_number(number)
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
    }

    pub fn block_by_hash(&self, hash: ExecutionBlockHash) -> Option<Block<T>> {
        self.blocks.get(&hash).cloned()
    }

    pub fn execution_block_by_hash(&self, hash: ExecutionBlockHash) -> Option<ExecutionBlock> {
        self.block_by_hash(hash)
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
    }

    pub fn execution_block_with_txs_by_hash(
        &self,
        hash: ExecutionBlockHash,
    ) -> Option<ExecutionBlockWithTransactions<T>> {
        self.block_by_hash(hash)
            .and_then(|block| block.as_execution_block_with_tx())
    }

    pub fn move_to_block_prior_to_terminal_block(&mut self) -> Result<(), String> {
        let target_block = self
            .terminal_block_number
            .checked_sub(1)
            .ok_or("terminal pow block is 0")?;
        self.move_to_pow_block(target_block)
    }

    pub fn move_to_terminal_block(&mut self) -> Result<(), String> {
        self.move_to_pow_block(self.terminal_block_number)
    }

    pub fn move_to_pow_block(&mut self, target_block: u64) -> Result<(), String> {
        let next_block = self.latest_block().unwrap().block_number() + 1;
        assert!(target_block >= next_block);

        self.insert_pow_blocks(next_block..=target_block)
    }

    pub fn drop_all_blocks(&mut self) {
        self.blocks = <_>::default();
        self.block_hashes = <_>::default();
    }

    pub fn insert_pow_blocks(
        &mut self,
        block_numbers: impl Iterator<Item = u64>,
    ) -> Result<(), String> {
        for i in block_numbers {
            self.insert_pow_block(i)?;
        }

        Ok(())
    }

    pub fn insert_pow_block(&mut self, block_number: u64) -> Result<(), String> {
        if let Some(finalized_block_hash) = self.finalized_block_hash {
            return Err(format!(
                "terminal block {} has been finalized. PoW chain has stopped building",
                finalized_block_hash
            ));
        }
        let parent_hash = if block_number == 0 {
            ExecutionBlockHash::zero()
        } else if let Some(block) = self.block_by_number(block_number - 1) {
            block.block_hash()
        } else {
            return Err(format!(
                "parent with block number {} not found",
                block_number - 1
            ));
        };

        let block = generate_pow_block(
            self.terminal_total_difficulty,
            self.terminal_block_number,
            block_number,
            parent_hash,
        )?;

        // Insert block into block tree
        self.insert_block(Block::PoW(block))?;

        // Set head
        if let Some(head_total_difficulty) =
            self.head_block.as_ref().and_then(|b| b.total_difficulty())
        {
            if block.total_difficulty >= head_total_difficulty {
                self.head_block = Some(Block::PoW(block));
            }
        } else {
            self.head_block = Some(Block::PoW(block));
        }
        Ok(())
    }

    /// Insert a PoW block given the parent hash.
    ///
    /// Returns `Ok(hash)` of the inserted block.
    /// Returns an error if the `parent_hash` does not exist in the block tree or
    /// if the parent block is the terminal block.
    pub fn insert_pow_block_by_hash(
        &mut self,
        parent_hash: ExecutionBlockHash,
        unique_id: u64,
    ) -> Result<ExecutionBlockHash, String> {
        let parent_block = self.block_by_hash(parent_hash).ok_or_else(|| {
            format!(
                "Block corresponding to parent hash does not exist: {}",
                parent_hash
            )
        })?;

        let mut block = generate_pow_block(
            self.terminal_total_difficulty,
            self.terminal_block_number,
            parent_block.block_number() + 1,
            parent_hash,
        )?;

        // Hack the block hash to make this block distinct from any other block with a different
        // `unique_id` (the default is 0).
        block.block_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(unique_id));
        block.block_hash = ExecutionBlockHash::from_root(block.tree_hash_root());

        let hash = self.insert_block(Block::PoW(block))?;

        // Set head
        if let Some(head_total_difficulty) =
            self.head_block.as_ref().and_then(|b| b.total_difficulty())
        {
            if block.total_difficulty >= head_total_difficulty {
                self.head_block = Some(Block::PoW(block));
            }
        } else {
            self.head_block = Some(Block::PoW(block));
        }
        Ok(hash)
    }

    pub fn insert_block(&mut self, block: Block<T>) -> Result<ExecutionBlockHash, String> {
        if self.blocks.contains_key(&block.block_hash()) {
            return Err(format!("{:?} is already known", block.block_hash()));
        } else if block.parent_hash() != ExecutionBlockHash::zero()
            && !self.blocks.contains_key(&block.parent_hash())
        {
            return Err(format!("parent block {:?} is unknown", block.parent_hash()));
        }

        Ok(self.insert_block_without_checks(block))
    }

    pub fn insert_block_without_checks(&mut self, block: Block<T>) -> ExecutionBlockHash {
        let block_hash = block.block_hash();
        self.block_hashes
            .entry(block.block_number())
            .or_insert_with(Vec::new)
            .push(block_hash);
        self.blocks.insert(block_hash, block);

        block_hash
    }

    pub fn modify_last_block(&mut self, block_modifier: impl FnOnce(&mut Block<T>)) {
        if let Some(last_block_hash) = self
            .block_hashes
            .iter_mut()
            .max_by_key(|(block_number, _)| *block_number)
            .and_then(|(_, block_hashes)| {
                // Remove block hash, we will re-insert with the new block hash after modifying it.
                block_hashes.pop()
            })
        {
            let mut block = self.blocks.remove(&last_block_hash).unwrap();
            block_modifier(&mut block);

            // Update the block hash after modifying the block
            match &mut block {
                Block::PoW(b) => b.block_hash = ExecutionBlockHash::from_root(b.tree_hash_root()),
                Block::PoS(b) => {
                    *b.block_hash_mut() = ExecutionBlockHash::from_root(b.tree_hash_root())
                }
            }

            // Update head.
            if self
                .head_block
                .as_ref()
                .map_or(true, |head| head.block_hash() == last_block_hash)
            {
                self.head_block = Some(block.clone());
            }

            self.insert_block_without_checks(block);
        }
    }

    pub fn get_payload(&mut self, id: &PayloadId) -> Option<ExecutionPayload<T>> {
        self.payload_ids.get(id).cloned()
    }

    pub fn new_payload(&mut self, payload: ExecutionPayload<T>) -> PayloadStatusV1 {
        let parent = if let Some(parent) = self.blocks.get(&payload.parent_hash()) {
            parent
        } else {
            return PayloadStatusV1 {
                status: PayloadStatusV1Status::Syncing,
                latest_valid_hash: None,
                validation_error: None,
            };
        };

        if payload.block_number() != parent.block_number() + 1 {
            return PayloadStatusV1 {
                status: PayloadStatusV1Status::Invalid,
                latest_valid_hash: Some(parent.block_hash()),
                validation_error: Some("invalid block number".to_string()),
            };
        }

        let valid_hash = payload.block_hash();
        self.pending_payloads.insert(payload.block_hash(), payload);

        PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: Some(valid_hash),
            validation_error: None,
        }
    }

    // This function expects payload_attributes to already be validated with respect to
    // the current fork [obtained by self.get_fork_at_timestamp(payload_attributes.timestamp)]
    pub fn forkchoice_updated(
        &mut self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<JsonForkchoiceUpdatedV1Response, String> {
        if let Some(payload) = self
            .pending_payloads
            .remove(&forkchoice_state.head_block_hash)
        {
            self.insert_block(Block::PoS(payload))?;
        }

        let unknown_head_block_hash = !self.blocks.contains_key(&forkchoice_state.head_block_hash);
        let unknown_safe_block_hash = forkchoice_state.safe_block_hash
            != ExecutionBlockHash::zero()
            && !self.blocks.contains_key(&forkchoice_state.safe_block_hash);
        let unknown_finalized_block_hash = forkchoice_state.finalized_block_hash
            != ExecutionBlockHash::zero()
            && !self
                .blocks
                .contains_key(&forkchoice_state.finalized_block_hash);

        if unknown_head_block_hash || unknown_safe_block_hash || unknown_finalized_block_hash {
            return Ok(JsonForkchoiceUpdatedV1Response {
                payload_status: JsonPayloadStatusV1 {
                    status: JsonPayloadStatusV1Status::Syncing,
                    latest_valid_hash: None,
                    validation_error: None,
                },
                payload_id: None,
            });
        }

        let id = match payload_attributes {
            None => None,
            Some(attributes) => {
                if !self.blocks.iter().any(|(_, block)| {
                    block.block_hash() == self.terminal_block_hash
                        || block.block_number() == self.terminal_block_number
                }) {
                    return Err("refusing to create payload id before terminal block".to_string());
                }

                let parent = self
                    .blocks
                    .get(&forkchoice_state.head_block_hash)
                    .ok_or_else(|| {
                        format!(
                            "unknown parent block {:?}",
                            forkchoice_state.head_block_hash
                        )
                    })?;

                let id = payload_id_from_u64(self.next_payload_id);
                self.next_payload_id += 1;

                let mut execution_payload = match &attributes {
                    PayloadAttributes::V1(pa) => ExecutionPayload::Merge(ExecutionPayloadMerge {
                        parent_hash: forkchoice_state.head_block_hash,
                        fee_recipient: pa.suggested_fee_recipient,
                        receipts_root: Hash256::repeat_byte(42),
                        state_root: Hash256::repeat_byte(43),
                        logs_bloom: vec![0; 256].into(),
                        prev_randao: pa.prev_randao,
                        block_number: parent.block_number() + 1,
                        gas_limit: GAS_LIMIT,
                        gas_used: GAS_USED,
                        timestamp: pa.timestamp,
                        extra_data: "block gen was here".as_bytes().to_vec().into(),
                        base_fee_per_gas: Uint256::one(),
                        block_hash: ExecutionBlockHash::zero(),
                        transactions: vec![].into(),
                    }),
                    PayloadAttributes::V2(pa) => {
                        match self.get_fork_at_timestamp(pa.timestamp) {
                            ForkName::Merge => ExecutionPayload::Merge(ExecutionPayloadMerge {
                                parent_hash: forkchoice_state.head_block_hash,
                                fee_recipient: pa.suggested_fee_recipient,
                                receipts_root: Hash256::repeat_byte(42),
                                state_root: Hash256::repeat_byte(43),
                                logs_bloom: vec![0; 256].into(),
                                prev_randao: pa.prev_randao,
                                block_number: parent.block_number() + 1,
                                gas_limit: GAS_LIMIT,
                                gas_used: GAS_USED,
                                timestamp: pa.timestamp,
                                extra_data: "block gen was here".as_bytes().to_vec().into(),
                                base_fee_per_gas: Uint256::one(),
                                block_hash: ExecutionBlockHash::zero(),
                                transactions: vec![].into(),
                            }),
                            ForkName::Capella => {
                                ExecutionPayload::Capella(ExecutionPayloadCapella {
                                    parent_hash: forkchoice_state.head_block_hash,
                                    fee_recipient: pa.suggested_fee_recipient,
                                    receipts_root: Hash256::repeat_byte(42),
                                    state_root: Hash256::repeat_byte(43),
                                    logs_bloom: vec![0; 256].into(),
                                    prev_randao: pa.prev_randao,
                                    block_number: parent.block_number() + 1,
                                    gas_limit: GAS_LIMIT,
                                    gas_used: GAS_USED,
                                    timestamp: pa.timestamp,
                                    extra_data: "block gen was here".as_bytes().to_vec().into(),
                                    base_fee_per_gas: Uint256::one(),
                                    block_hash: ExecutionBlockHash::zero(),
                                    transactions: vec![].into(),
                                    withdrawals: pa.withdrawals.as_ref().unwrap().clone().into(),
                                })
                            }
                            ForkName::Eip4844 => {
                                ExecutionPayload::Eip4844(ExecutionPayloadEip4844 {
                                    parent_hash: forkchoice_state.head_block_hash,
                                    fee_recipient: pa.suggested_fee_recipient,
                                    receipts_root: Hash256::repeat_byte(42),
                                    state_root: Hash256::repeat_byte(43),
                                    logs_bloom: vec![0; 256].into(),
                                    prev_randao: pa.prev_randao,
                                    block_number: parent.block_number() + 1,
                                    gas_limit: GAS_LIMIT,
                                    gas_used: GAS_USED,
                                    timestamp: pa.timestamp,
                                    extra_data: "block gen was here".as_bytes().to_vec().into(),
                                    base_fee_per_gas: Uint256::one(),
                                    // FIXME(4844): maybe this should be set to something?
                                    excess_data_gas: Uint256::one(),
                                    block_hash: ExecutionBlockHash::zero(),
                                    transactions: vec![].into(),
                                    withdrawals: pa.withdrawals.as_ref().unwrap().clone().into(),
                                })
                            }
                            _ => unreachable!(),
                        }
                    }
                };

                *execution_payload.block_hash_mut() =
                    ExecutionBlockHash::from_root(execution_payload.tree_hash_root());

                self.payload_ids.insert(id, execution_payload);

                Some(id)
            }
        };

        self.head_block = Some(
            self.blocks
                .get(&forkchoice_state.head_block_hash)
                .unwrap()
                .clone(),
        );

        if forkchoice_state.finalized_block_hash != ExecutionBlockHash::zero() {
            self.finalized_block_hash = Some(forkchoice_state.finalized_block_hash);
        }

        Ok(JsonForkchoiceUpdatedV1Response {
            payload_status: JsonPayloadStatusV1 {
                status: JsonPayloadStatusV1Status::Valid,
                latest_valid_hash: Some(forkchoice_state.head_block_hash),
                validation_error: None,
            },
            payload_id: id.map(Into::into),
        })
    }
}

fn payload_id_from_u64(n: u64) -> PayloadId {
    n.to_le_bytes()
}

pub fn generate_pow_block(
    terminal_total_difficulty: Uint256,
    terminal_block_number: u64,
    block_number: u64,
    parent_hash: ExecutionBlockHash,
) -> Result<PoWBlock, String> {
    if block_number > terminal_block_number {
        return Err(format!(
            "{} is beyond terminal pow block {}",
            block_number, terminal_block_number
        ));
    }

    let total_difficulty = if block_number == terminal_block_number {
        terminal_total_difficulty
    } else {
        let increment = terminal_total_difficulty
            .checked_div(Uint256::from(terminal_block_number))
            .expect("terminal block number must be non-zero");
        increment
            .checked_mul(Uint256::from(block_number))
            .expect("overflow computing total difficulty")
    };

    let mut block = PoWBlock {
        block_number,
        block_hash: ExecutionBlockHash::zero(),
        parent_hash,
        total_difficulty,
        timestamp: block_number,
    };

    block.block_hash = ExecutionBlockHash::from_root(block.tree_hash_root());

    Ok(block)
}

#[cfg(test)]
mod test {
    use super::*;
    use types::MainnetEthSpec;

    #[test]
    fn pow_chain_only() {
        const TERMINAL_DIFFICULTY: u64 = 10;
        const TERMINAL_BLOCK: u64 = 10;
        const DIFFICULTY_INCREMENT: u64 = 1;

        let mut generator: ExecutionBlockGenerator<MainnetEthSpec> = ExecutionBlockGenerator::new(
            TERMINAL_DIFFICULTY.into(),
            TERMINAL_BLOCK,
            ExecutionBlockHash::zero(),
            None,
            None,
        );

        for i in 0..=TERMINAL_BLOCK {
            if i > 0 {
                generator.insert_pow_block(i).unwrap();
            }

            /*
             * Generate a block, inspect it.
             */

            let block = generator.latest_block().unwrap();
            assert_eq!(block.block_number(), i);

            let expected_parent = i
                .checked_sub(1)
                .map(|i| generator.block_by_number(i).unwrap().block_hash())
                .unwrap_or_else(ExecutionBlockHash::zero);
            assert_eq!(block.parent_hash(), expected_parent);

            assert_eq!(
                block.total_difficulty().unwrap(),
                (i * DIFFICULTY_INCREMENT).into()
            );

            assert_eq!(generator.block_by_hash(block.block_hash()).unwrap(), block);
            assert_eq!(generator.block_by_number(i).unwrap(), block);

            /*
             * Check the parent is accessible.
             */

            if let Some(prev_i) = i.checked_sub(1) {
                assert_eq!(
                    generator.block_by_number(prev_i).unwrap(),
                    generator.block_by_hash(block.parent_hash()).unwrap()
                );
            }

            /*
             * Check the next block is inaccessible.
             */

            let next_i = i + 1;
            assert!(generator.block_by_number(next_i).is_none());
        }
    }
}
