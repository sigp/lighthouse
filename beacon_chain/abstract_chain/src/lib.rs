/*
 * <Block><Block><Block><Block>
 */


use hashing::canonical_hash;
use ssz::{Encodable, Decodable, DecodeError, SszStream, ssz_encode};
use std::collections::{HashMap, HashSet};
use types::Hash256;

mod block_reader;

use crate::block_reader::BlockReader;

pub trait AbstractChain {
    type Block;
    type Hash;

    fn genesis(&mut self);

    fn receive_block(&mut self, block: &BlockReader) -> bool;

    fn block_by_root(&self, root: &Self::Hash) -> Option<&Self::Block>;
}

pub struct TestBlock {
    slot: u64,
    parent_root: Hash256,
    state_root: Hash256,
    weight: u8,
}

impl Encodable for TestBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.parent_root);
    }
}

impl Decodable for TestBlock {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (parent_root, i) = <_>::ssz_decode(bytes, i)?;
        let (state_root, i) = <_>::ssz_decode(bytes, i)?;
        let (weight, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                parent_root,
                state_root,
                weight,
            },
            i,
        ))
    }
}

impl TestBlock {
    fn canonical_hash(&self) -> Hash256 {
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }
}

impl BlockReader for TestBlock {
    fn slot(&self) -> u64 {
        self.slot
    }

    fn parent_root(&self) -> Hash256 {
        self.parent_root
    }
}

#[derive(Clone)]
pub struct TestState {
    total_weight: u64,
    skipped_slots: u64,
}

impl Encodable for TestState {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.total_weight);
        s.append(&self.skipped_slots);
    }
}

impl TestState {
    fn canonical_hash(&self) -> Hash256 {
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }
}

impl Decodable for TestState {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (total_weight, i) = <_>::ssz_decode(bytes, i)?;
        let (skipped_slots, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                total_weight,
                skipped_slots,
            },
            i,
        ))
    }
}

pub struct TestChain {
    slot: u64,
    block_store: HashMap<Hash256, TestBlock>,
    state_store: HashMap<Hash256, TestState>,
    leaf_nodes: HashSet<Hash256>,
    canonical_leaf_node: Hash256,
}

impl AbstractChain for TestChain {
    type Block = TestBlock;
    type Hash = Hash256;

    fn genesis(&mut self) {
        let genesis_state = TestState {
            total_weight: 255,
            skipped_slots: 0,
        };
        let state_root = genesis_state.canonical_hash();
        let genesis_block = TestBlock {
            slot: 0,
            parent_root: Hash256::zero(),
            state_root: state_root.clone(),
            weight: 255,
        };
        let block_root = genesis_block.canonical_hash();
        self.block_store.insert(block_root, genesis_block);
        self.state_store.insert(state_root, genesis_state);
        self.leaf_nodes.insert(block_root);
        self.canonical_leaf_node = block_root;
        self.slot = 0;
    }

    fn block_by_root(&self, root: &Hash256) -> Option<&Self::Block> {
        self.block_store.get(root)
    }

    fn receive_block(&mut self, block: &BlockReader) -> bool {
        let block_hash = block.canonical_hash();
        let parent_block = match self.block_by_root(&block.parent_root()) {
            Some(block) => block,
            None => return false
        };
        let slot_distance = block.slot().saturating_sub(parent_block.slot());
        if slot_distance > 0 {
            let mut state = self.state_store.get(&block.parent_root()).unwrap().clone();
            for _ in parent_block.slot()..(block.slot() - 1) {
                state.skipped_slots += 1;
            }
            state.total_weight += u64::from(block.weight);
            let state_root = state.canonical_hash();
            if state_root != block.state_root {
                return false;
            }
            self.leaf_nodes.remove(&block.parent_root());
            self.leaf_nodes.insert(block_hash);

            let canonical_state = {
                let canonical_block = self.block_store.get(&self.canonical_leaf_node).unwrap();
                self.state_store.get(&canonical_block.state_root).unwrap()
            };
            // New block is canonical, chain weight is greatest.
            if state.total_weight > canonical_state.total_weight {
                self.canonical_leaf_node = block_hash;
            }
            // New block chain weight equals existing canonical block chain weight.
            else if state.total_weight == canonical_state.total_weight {
                // New block is canonical as hash is highest.
                if block_hash > self.canonical_leaf_node {
                    self.canonical_leaf_node = block_hash;
                }
            }
            true
        } else {
            false
        }
    }
}
