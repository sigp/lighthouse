use crate::engine_api::{http::JsonPreparePayloadRequest, ExecutePayloadResponse, ExecutionBlock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::{EthSpec, ExecutionPayload, Hash256, Uint256};

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
            Block::PoS(payload) => payload.block_number,
        }
    }

    pub fn parent_hash(&self) -> Hash256 {
        match self {
            Block::PoW(block) => block.parent_hash,
            Block::PoS(payload) => payload.parent_hash,
        }
    }

    pub fn block_hash(&self) -> Hash256 {
        match self {
            Block::PoW(block) => block.block_hash,
            Block::PoS(payload) => payload.block_hash,
        }
    }

    pub fn total_difficulty(&self) -> Option<Uint256> {
        match self {
            Block::PoW(block) => Some(block.total_difficulty),
            Block::PoS(_) => None,
        }
    }

    pub fn as_execution_block(&self, total_difficulty: u64) -> ExecutionBlock {
        match self {
            Block::PoW(block) => ExecutionBlock {
                block_hash: block.block_hash,
                block_number: block.block_number,
                parent_hash: block.parent_hash,
                total_difficulty: block.total_difficulty,
            },
            Block::PoS(payload) => ExecutionBlock {
                block_hash: payload.block_hash,
                block_number: payload.block_number,
                parent_hash: payload.parent_hash,
                total_difficulty: total_difficulty.into(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct PoWBlock {
    pub block_number: u64,
    pub block_hash: Hash256,
    pub parent_hash: Hash256,
    pub total_difficulty: Uint256,
}

pub struct ExecutionBlockGenerator<T: EthSpec> {
    /*
     * Common database
     */
    blocks: HashMap<Hash256, Block<T>>,
    block_hashes: HashMap<u64, Hash256>,
    /*
     * PoW block parameters
     */
    pub terminal_total_difficulty: u64,
    pub terminal_block_number: u64,
    /*
     * PoS block parameters
     */
    pub pending_payloads: HashMap<Hash256, ExecutionPayload<T>>,
    pub next_payload_id: u64,
    pub payload_ids: HashMap<u64, ExecutionPayload<T>>,
}

impl<T: EthSpec> ExecutionBlockGenerator<T> {
    pub fn new(terminal_total_difficulty: u64, terminal_block_number: u64) -> Self {
        let mut gen = Self {
            blocks: <_>::default(),
            block_hashes: <_>::default(),
            terminal_total_difficulty,
            terminal_block_number,
            pending_payloads: <_>::default(),
            next_payload_id: 0,
            payload_ids: <_>::default(),
        };

        gen.insert_pow_block(0).unwrap();

        gen
    }

    pub fn latest_block(&self) -> Option<Block<T>> {
        let hash = *self
            .block_hashes
            .iter()
            .max_by_key(|(number, _)| *number)
            .map(|(_, hash)| hash)?;

        self.block_by_hash(hash)
    }

    pub fn latest_execution_block(&self) -> Option<ExecutionBlock> {
        self.latest_block()
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
    }

    pub fn block_by_number(&self, number: u64) -> Option<Block<T>> {
        let hash = *self.block_hashes.get(&number)?;
        self.block_by_hash(hash)
    }

    pub fn execution_block_by_number(&self, number: u64) -> Option<ExecutionBlock> {
        self.block_by_number(number)
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
    }

    pub fn block_by_hash(&self, hash: Hash256) -> Option<Block<T>> {
        self.blocks.get(&hash).cloned()
    }

    pub fn execution_block_by_hash(&self, hash: Hash256) -> Option<ExecutionBlock> {
        self.block_by_hash(hash)
            .map(|block| block.as_execution_block(self.terminal_total_difficulty))
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
        if block_number > self.terminal_block_number {
            return Err(format!(
                "{} is beyond terminal pow block {}",
                block_number, self.terminal_block_number
            ));
        }

        let parent_hash = if block_number == 0 {
            Hash256::zero()
        } else if let Some(hash) = self.block_hashes.get(&(block_number - 1)) {
            *hash
        } else {
            return Err(format!(
                "parent with block number {} not found",
                block_number - 1
            ));
        };

        let increment = self
            .terminal_total_difficulty
            .checked_div(self.terminal_block_number)
            .expect("terminal block number must be non-zero");
        let total_difficulty = increment
            .checked_mul(block_number)
            .expect("overflow computing total difficulty")
            .into();

        let mut block = PoWBlock {
            block_number,
            block_hash: Hash256::zero(),
            parent_hash,
            total_difficulty,
        };

        block.block_hash = block.tree_hash_root();

        self.block_hashes
            .insert(block.block_number, block.block_hash);
        self.blocks.insert(block.block_hash, Block::PoW(block));

        Ok(())
    }

    pub fn prepare_payload_id(
        &mut self,
        payload: JsonPreparePayloadRequest,
    ) -> Result<u64, String> {
        if !self
            .blocks
            .iter()
            .any(|(_, block)| block.block_number() == self.terminal_block_number)
        {
            return Err("refusing to create payload id before terminal block".to_string());
        }

        let parent = self
            .blocks
            .get(&payload.parent_hash)
            .ok_or_else(|| format!("unknown parent block {:?}", payload.parent_hash))?;

        let id = self.next_payload_id;
        self.next_payload_id += 1;

        let mut execution_payload = ExecutionPayload {
            parent_hash: payload.parent_hash,
            coinbase: payload.fee_recipient,
            receipt_root: Hash256::repeat_byte(42),
            state_root: Hash256::repeat_byte(43),
            logs_bloom: vec![0; 256].into(),
            random: payload.random,
            block_number: parent.block_number() + 1,
            gas_limit: 10,
            gas_used: 9,
            timestamp: payload.timestamp,
            extra_data: vec![].into(),
            base_fee_per_gas: Hash256::from_low_u64_be(1),
            block_hash: Hash256::zero(),
            transactions: vec![].into(),
        };

        execution_payload.block_hash = execution_payload.tree_hash_root();

        self.payload_ids.insert(id, execution_payload);

        Ok(id)
    }

    pub fn get_payload(&mut self, id: u64) -> Option<ExecutionPayload<T>> {
        self.payload_ids.remove(&id)
    }

    pub fn execute_payload(&mut self, payload: ExecutionPayload<T>) -> ExecutePayloadResponse {
        let parent = if let Some(parent) = self.blocks.get(&payload.parent_hash) {
            parent
        } else {
            return ExecutePayloadResponse::Invalid;
        };

        if payload.block_number != parent.block_number() + 1 {
            return ExecutePayloadResponse::Invalid;
        }

        self.pending_payloads.insert(payload.block_hash, payload);

        ExecutePayloadResponse::Valid
    }
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

        let mut generator: ExecutionBlockGenerator<MainnetEthSpec> =
            ExecutionBlockGenerator::new(TERMINAL_DIFFICULTY, TERMINAL_BLOCK);

        for i in 0..=TERMINAL_BLOCK {
            generator.insert_pow_block(i).unwrap();

            /*
             * Generate a block, inspect it.
             */

            let block = generator.latest_block().unwrap();
            assert_eq!(block.block_number(), i);

            let expected_parent = i
                .checked_sub(1)
                .map(|i| generator.block_by_number(i).unwrap().block_hash())
                .unwrap_or_else(Hash256::zero);
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

    /*
    #[test]
    fn pos_blocks() {
        const TERMINAL_DIFFICULTY: u64 = 10;
        const TERMINAL_BLOCK: u64 = 10;

        let mut generator: ExecutionBlockGenerator<MainnetEthSpec> =
            ExecutionBlockGenerator::new(TERMINAL_DIFFICULTY, TERMINAL_BLOCK);

        let penultimate_pow_block = generator.terminal_block_number.checked_sub(1).unwrap();
        let last_pow_block = generator.terminal_block_number;
        let first_pos_block = generator.terminal_block_number + 1;
        let second_pos_block = first_pos_block + 1;

        generator.insert_pow_blocks(0..=penultimate_pow_block);

        assert!(generator.block_by_number(last_pow_block).is_none());

        assert!(generator.insert_pos_block(first_pos_block).is_err());

        generator.set_clock_for_block_number(last_pow_block);

        generator.block_by_number(last_pow_block).unwrap();

        assert!(generator.block_by_number(first_pos_block).is_none());

        generator.insert_pos_block(first_pos_block).unwrap();

        generator.block_by_number(first_pos_block).unwrap();

        assert!(generator.insert_pos_block(first_pos_block).is_err());

        generator.insert_pos_block(second_pos_block).unwrap();
    }
    */
}
