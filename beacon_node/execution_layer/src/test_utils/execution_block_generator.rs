use crate::engine_api::{http::JsonPreparePayloadRequest, ExecutePayloadResponse};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use tree_hash::TreeHash;
use types::{EthSpec, ExecutionPayload, Hash256, Uint256};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub block_number: u64,
    pub block_hash: Hash256,
    pub parent_hash: Hash256,
    pub total_difficulty: Uint256,
}

pub struct ExecutionBlockGenerator<T: EthSpec> {
    /*
     * PoW block parameters
     */
    pub seconds_since_genesis: u64,
    pub block_interval_secs: u64,
    pub terminal_total_difficulty: u64,
    pub terminal_block_number: u64,
    /*
     * PoS block parameters
     */
    pub pending_payloads: HashMap<Hash256, ExecutionPayload<T>>,
    pub merge_blocks: HashMap<Hash256, ExecutionPayload<T>>,
    pub merge_block_numbers: HashMap<u64, Hash256>,
    pub latest_merge_block: Option<u64>,
    pub next_payload_id: u64,
    pub payload_ids: HashMap<u64, ExecutionPayload<T>>,
}

impl<T: EthSpec> ExecutionBlockGenerator<T> {
    pub fn new(terminal_total_difficulty: u64, terminal_block_number: u64) -> Self {
        Self {
            // PoW params
            seconds_since_genesis: 0,
            block_interval_secs: 1,
            terminal_total_difficulty,
            terminal_block_number,
            // PoS params
            pending_payloads: <_>::default(),
            merge_blocks: <_>::default(),
            merge_block_numbers: <_>::default(),
            latest_merge_block: None,
            next_payload_id: 0,
            payload_ids: <_>::default(),
        }
    }

    pub fn set_clock_for_block_number(&mut self, number: u64) {
        self.seconds_since_genesis = number
            .checked_mul(self.block_interval_secs)
            .expect("overflow setting clock");
    }

    pub fn increment_seconds_since_genesis(&mut self, inc: u64) {
        self.seconds_since_genesis += inc;
    }

    fn block_number_at(&self, unix_seconds: u64) -> u64 {
        unix_seconds
            .checked_div(self.block_interval_secs)
            .expect("block interval cannot be zero")
    }

    fn total_difficulty_for_block(&self, number: u64) -> u64 {
        if number >= self.terminal_block_number {
            self.terminal_total_difficulty
        } else {
            let increment = self
                .terminal_total_difficulty
                .checked_div(self.terminal_block_number)
                .expect("terminal block number must be non-zero");
            increment
                .checked_mul(number)
                .expect("overflow computing total difficulty")
        }
    }

    fn sanitize_pos_block_number(&self, number: u64) -> Result<(), String> {
        if number <= self.terminal_block_number {
            return Err(format!(
                "cannot insert block {} as it is prior to terminal block {}",
                number, self.terminal_block_number
            ));
        }

        let time_based_block = self.block_number_at(self.seconds_since_genesis);
        if time_based_block < self.terminal_block_number && number > time_based_block {
            return Err(format!("it is too early to insert block {}", number));
        }

        let next_block = self
            .latest_merge_block
            .unwrap_or(self.terminal_block_number)
            + 1;

        match number.cmp(&next_block) {
            Ordering::Equal => Ok(()),
            Ordering::Less => Err(format!(
                "cannot insert block {} which already exists",
                number
            )),
            Ordering::Greater => Err(format!(
                "cannot insert block {} before inserting {}",
                number, next_block
            )),
        }
    }

    pub fn prepare_payload_id(
        &mut self,
        payload: JsonPreparePayloadRequest,
    ) -> Result<u64, String> {
        if self.block_number_at(self.seconds_since_genesis) < self.terminal_block_number {
            return Err("refusing to create payload id before terminal block".to_string());
        }

        let parent = self
            .block_by_hash(payload.parent_hash)
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
            block_number: parent.block_number + 1,
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
        let parent = if let Some(parent) = self.block_by_hash(payload.parent_hash) {
            parent
        } else {
            return ExecutePayloadResponse::Invalid;
        };

        if payload.block_number != parent.block_number + 1 {
            return ExecutePayloadResponse::Invalid;
        }

        self.pending_payloads.insert(payload.block_hash, payload);

        ExecutePayloadResponse::Valid
    }

    pub fn insert_pos_block(&mut self, number: u64) -> Result<(), String> {
        self.sanitize_pos_block_number(number)?;
        self.latest_merge_block = Some(number);
        Ok(())
    }

    fn latest_block_number(&self) -> u64 {
        let time_based = self.block_number_at(self.seconds_since_genesis);

        if time_based < self.terminal_block_number {
            time_based
        } else {
            self.latest_merge_block
                .unwrap_or(self.terminal_block_number)
        }
    }

    pub fn latest_block(&self) -> Option<Block> {
        self.block_by_number(self.latest_block_number())
    }

    pub fn block_by_number(&self, number: u64) -> Option<Block> {
        let parent_hash = number
            .checked_sub(1)
            .map(block_number_to_hash)
            .unwrap_or_else(Hash256::zero);
        let block_hash = block_number_to_hash(number);

        if number <= self.terminal_block_number {
            if number <= self.latest_block_number() {
                Some(Block {
                    block_number: number,
                    block_hash,
                    parent_hash,
                    total_difficulty: Uint256::from(self.total_difficulty_for_block(number)),
                })
            } else {
                None
            }
        } else {
            let latest_block = self
                .latest_merge_block
                .unwrap_or(self.terminal_block_number);

            if number <= latest_block {
                Some(Block {
                    block_number: number,
                    block_hash,
                    parent_hash,
                    total_difficulty: Uint256::from(self.terminal_total_difficulty),
                })
            } else {
                None
            }
        }
    }

    pub fn block_by_hash(&self, hash: Hash256) -> Option<Block> {
        let block_number = block_hash_to_number(hash);
        self.block_by_number(block_number)
    }
}

pub fn block_number_to_hash(n: u64) -> Hash256 {
    Hash256::from_low_u64_be(n + 1)
}

pub fn block_hash_to_number(hash: Hash256) -> u64 {
    hash.to_low_u64_be()
        .checked_sub(1)
        .expect("do not query for zero hash")
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

        for mut i in 0..(TERMINAL_BLOCK + 5) {
            i = std::cmp::min(i, TERMINAL_BLOCK);

            /*
             * Generate a block, inspect it.
             */

            let block = generator.latest_block().unwrap();
            assert_eq!(block.block_hash, block_number_to_hash(i));
            assert_eq!(block_hash_to_number(block.block_hash), i);

            let expected_parent = i
                .checked_sub(1)
                .map(block_number_to_hash)
                .unwrap_or_else(Hash256::zero);
            assert_eq!(block.parent_hash, expected_parent);

            assert_eq!(block.total_difficulty, (i * DIFFICULTY_INCREMENT).into());

            assert_eq!(generator.block_by_hash(block.block_hash).unwrap(), block);
            assert_eq!(generator.block_by_number(i).unwrap(), block);

            /*
             * Check the parent is accessible.
             */

            if let Some(prev_i) = i.checked_sub(1) {
                assert_eq!(
                    generator.block_by_number(prev_i).unwrap(),
                    generator.block_by_hash(block.parent_hash).unwrap()
                );
            }

            /*
             * Check the next block is inaccessible.
             */

            let next_i = i + 1;
            assert!(generator.block_by_number(next_i).is_none());
            assert!(generator
                .block_by_hash(block_number_to_hash(next_i))
                .is_none());

            generator.increment_seconds_since_genesis(1);
        }
    }

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

        generator.set_clock_for_block_number(penultimate_pow_block);

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
}
