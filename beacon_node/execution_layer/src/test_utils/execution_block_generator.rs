use crate::engine_api::{
    ExecutePayloadResponse, ExecutePayloadResponseStatus, ExecutionBlock, PayloadAttributes,
    PayloadId,
};
use crate::engines::ForkChoiceState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::{EthSpec, ExecutionPayload, Hash256, Uint256};

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

    pub fn as_execution_block(&self, total_difficulty: Uint256) -> ExecutionBlock {
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
                total_difficulty,
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
    pub terminal_total_difficulty: Uint256,
    pub terminal_block_number: u64,
    pub terminal_block_hash: Hash256,
    /*
     * PoS block parameters
     */
    pub pending_payloads: HashMap<Hash256, ExecutionPayload<T>>,
    pub next_payload_id: u64,
    pub payload_ids: HashMap<PayloadId, ExecutionPayload<T>>,
}

impl<T: EthSpec> ExecutionBlockGenerator<T> {
    pub fn new(
        terminal_total_difficulty: Uint256,
        terminal_block_number: u64,
        terminal_block_hash: Hash256,
    ) -> Self {
        let mut gen = Self {
            blocks: <_>::default(),
            block_hashes: <_>::default(),
            terminal_total_difficulty,
            terminal_block_number,
            terminal_block_hash,
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

        let block = generate_pow_block(
            self.terminal_total_difficulty,
            self.terminal_block_number,
            block_number,
            parent_hash,
        )?;

        self.insert_block(Block::PoW(block))
    }

    pub fn insert_block(&mut self, block: Block<T>) -> Result<(), String> {
        if self.blocks.contains_key(&block.block_hash()) {
            return Err(format!("{:?} is already known", block.block_hash()));
        } else if self.block_hashes.contains_key(&block.block_number()) {
            return Err(format!(
                "block {} is already known, forking is not supported",
                block.block_number()
            ));
        } else if block.block_number() != 0 && !self.blocks.contains_key(&block.parent_hash()) {
            return Err(format!("parent block {:?} is unknown", block.parent_hash()));
        }

        self.insert_block_without_checks(block)
    }

    pub fn insert_block_without_checks(&mut self, block: Block<T>) -> Result<(), String> {
        self.block_hashes
            .insert(block.block_number(), block.block_hash());
        self.blocks.insert(block.block_hash(), block);

        Ok(())
    }

    pub fn get_payload(&mut self, id: &PayloadId) -> Option<ExecutionPayload<T>> {
        self.payload_ids.remove(id)
    }

    pub fn execute_payload(&mut self, payload: ExecutionPayload<T>) -> ExecutePayloadResponse {
        let parent = if let Some(parent) = self.blocks.get(&payload.parent_hash) {
            parent
        } else {
            return ExecutePayloadResponse {
                status: ExecutePayloadResponseStatus::Syncing,
                latest_valid_hash: None,
                message: None,
            };
        };

        if payload.block_number != parent.block_number() + 1 {
            return ExecutePayloadResponse {
                status: ExecutePayloadResponseStatus::Invalid,
                latest_valid_hash: Some(parent.block_hash()),
                message: Some("invalid block number".to_string()),
            };
        }

        let valid_hash = payload.block_hash;
        self.pending_payloads.insert(payload.block_hash, payload);

        ExecutePayloadResponse {
            status: ExecutePayloadResponseStatus::Valid,
            latest_valid_hash: Some(valid_hash),
            message: None,
        }
    }

    pub fn forkchoice_updated_v1(
        &mut self,
        forkchoice_state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<Option<PayloadId>, String> {
        if let Some(payload) = self
            .pending_payloads
            .remove(&forkchoice_state.head_block_hash)
        {
            self.insert_block(Block::PoS(payload))?;
        }
        if !self.blocks.contains_key(&forkchoice_state.head_block_hash) {
            return Err(format!(
                "block hash {:?} unknown",
                forkchoice_state.head_block_hash
            ));
        }
        if !self.blocks.contains_key(&forkchoice_state.safe_block_hash) {
            return Err(format!(
                "block hash {:?} unknown",
                forkchoice_state.head_block_hash
            ));
        }

        if forkchoice_state.finalized_block_hash != Hash256::zero()
            && !self
                .blocks
                .contains_key(&forkchoice_state.finalized_block_hash)
        {
            return Err(format!(
                "finalized block hash {:?} is unknown",
                forkchoice_state.finalized_block_hash
            ));
        }

        match payload_attributes {
            None => Ok(None),
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

                let mut execution_payload = ExecutionPayload {
                    parent_hash: forkchoice_state.head_block_hash,
                    coinbase: attributes.fee_recipient,
                    receipt_root: Hash256::repeat_byte(42),
                    state_root: Hash256::repeat_byte(43),
                    logs_bloom: vec![0; 256].into(),
                    random: attributes.random,
                    block_number: parent.block_number() + 1,
                    gas_limit: GAS_LIMIT,
                    gas_used: GAS_USED,
                    timestamp: attributes.timestamp,
                    extra_data: "block gen was here".as_bytes().to_vec().into(),
                    base_fee_per_gas: Uint256::one(),
                    block_hash: Hash256::zero(),
                    transactions: vec![].into(),
                };

                execution_payload.block_hash = execution_payload.tree_hash_root();

                self.payload_ids.insert(id, execution_payload);

                Ok(Some(id))
            }
        }
    }
}

fn payload_id_from_u64(n: u64) -> PayloadId {
    n.to_le_bytes()
}

pub fn generate_pow_block(
    terminal_total_difficulty: Uint256,
    terminal_block_number: u64,
    block_number: u64,
    parent_hash: Hash256,
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
        block_hash: Hash256::zero(),
        parent_hash,
        total_difficulty,
    };

    block.block_hash = block.tree_hash_root();

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
            Hash256::zero(),
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
}
