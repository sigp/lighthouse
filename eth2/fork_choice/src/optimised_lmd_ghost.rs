extern crate byteorder;
extern crate fast_math;
use crate::{ForkChoice, ForkChoiceError};
use byteorder::{BigEndian, ByteOrder};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB,
};
use fast_math::log2_raw;
use std::collections::HashMap;
use std::sync::Arc;
use types::{
    readers::{BeaconBlockReader, BeaconStateReader},
    validator_registry::get_active_validator_indices,
    BeaconBlock, Hash256,
};

//TODO: Sort out global constants
const GENESIS_SLOT: u64 = 0;
const FORK_CHOICE_BALANCE_INCREMENT: u64 = 1e9 as u64;
const MAX_DEPOSIT_AMOUNT: u64 = 32e9 as u64;

/// The optimised LMD-GHOST fork choice rule.
/// NOTE: This uses u32 to represent difference between block heights. Thus this is only
/// applicable for block height differences in the range of a u32.
/// This can potentially be parallelized in some parts.
// we use fast log2, a log2 lookup table is implemented in Vitaliks code, potentially do
// the comparison. Log2_raw takes 2ns according to the documentation.
#[inline]
fn log2_int(x: u32) -> u32 {
    log2_raw(x as f32) as u32
}

fn power_of_2_below(x: u32) -> u32 {
    2u32.pow(log2_int(x))
}

/// Stores the necessary data structures to run the optimised lmd ghost algorithm.
pub struct OptimisedLMDGhost<T: ClientDB + Sized> {
    /// A cache of known ancestors at given heights for a specific block.
    //TODO: Consider FnvHashMap
    cache: HashMap<CacheKey<u32>, Hash256>,
    /// Log lookup table for blocks to their ancestors.
    //TODO: Verify we only want/need a size 16 log lookup
    ancestors: Vec<HashMap<Hash256, Hash256>>,
    /// Stores the children for any given parent.
    children: HashMap<Hash256, Vec<Hash256>>,
    /// The latest attestation targets as a map of validator index to block hash.
    //TODO: Could this be a fixed size vec
    latest_attestation_targets: HashMap<u64, Hash256>,
    /// Block storage access.
    block_store: Arc<BeaconBlockStore<T>>,
    /// State storage access.
    state_store: Arc<BeaconStateStore<T>>,
    max_known_height: u64,
}

impl<T> OptimisedLMDGhost<T>
where
    T: ClientDB + Sized,
{
    pub fn new(block_store: BeaconBlockStore<T>, state_store: BeaconStateStore<T>) -> Self {
        OptimisedLMDGhost {
            cache: HashMap::new(),
            ancestors: vec![HashMap::new(); 16],
            latest_attestation_targets: HashMap::new(),
            children: HashMap::new(),
            max_known_height: 0,
            block_store: Arc::new(block_store),
            state_store: Arc::new(state_store),
        }
    }

    /// Gets the ancestor at a given height `at_height` of a block specified by `block_hash`.
    fn get_ancestor(&mut self, block_hash: Hash256, at_height: u32) -> Option<Hash256> {
        // return None if we can't get the block from the db.
        let block_height = {
            let block_slot = self
                .block_store
                .get_reader(&block_hash)
                .ok()?
                .expect("Should have returned already if None")
                .into_beacon_block()?
                .slot;

            (block_slot - GENESIS_SLOT) as u32
        };

        // verify we haven't exceeded the block height
        if at_height >= block_height {
            if at_height > block_height {
                return None;
            } else {
                return Some(block_hash);
            }
        }
        // check if the result is stored in our cache
        let cache_key = CacheKey::new(&block_hash, at_height);
        if let Some(ancestor) = self.cache.get(&cache_key) {
            return Some(*ancestor);
        }

        // not in the cache recursively search for ancestors using a log-lookup

        if let Some(ancestor) = {
            let ancestor_lookup = self.ancestors
                [log2_int((block_height - at_height - 1) as u32) as usize]
                .get(&block_hash)
                //TODO: Panic if we can't lookup and fork choice fails
                .expect("All blocks should be added to the ancestor log lookup table");
            self.get_ancestor(*ancestor_lookup, at_height)
        } {
            // add the result to the cache
            self.cache.insert(cache_key, ancestor);
            return Some(ancestor);
        }

        None
    }

    // looks for an obvious block winner given the latest votes for a specific height
    fn get_clear_winner(
        &mut self,
        latest_votes: &HashMap<Hash256, u64>,
        height: u64,
    ) -> Option<Hash256> {
        // map of vote counts for every hash at this height
        let mut current_votes: HashMap<Hash256, u64> = HashMap::new();
        let mut total_vote_count = 0;

        // loop through the latest votes and count all votes
        // these have already been weighted by balance
        for (hash, votes) in latest_votes.iter() {
            if let Some(ancestor) = self.get_ancestor(*hash, height as u32) {
                let current_vote_value = current_votes.get(&ancestor).unwrap_or_else(|| &0);
                current_votes.insert(ancestor, current_vote_value + *votes);
                total_vote_count += votes;
            }
        }
        // Check if there is a clear block winner at this height. If so return it.
        for (hash, votes) in current_votes.iter() {
            if *votes >= total_vote_count / 2 {
                // we have a clear winner, return it
                return Some(*hash);
            }
        }
        // didn't find a clear winner
        None
    }

    // Finds the best child, splitting children into a binary tree, based on their hashes
    fn choose_best_child(&self, votes: &HashMap<Hash256, u64>) -> Option<Hash256> {
        let mut bitmask = 0;
        for bit in (0..=255).rev() {
            let mut zero_votes = 0;
            let mut one_votes = 0;
            let mut single_candidate = None;

            for (candidate, votes) in votes.iter() {
                let candidate_uint = BigEndian::read_u32(candidate);
                if candidate_uint >> (bit + 1) != bitmask {
                    continue;
                }
                if (candidate_uint >> bit) % 2 == 0 {
                    zero_votes += votes;
                } else {
                    one_votes += votes;
                }

                if single_candidate.is_none() {
                    single_candidate = Some(candidate);
                } else {
                    single_candidate = None;
                }
            }
            bitmask = (bitmask * 2) + {
                if one_votes > zero_votes {
                    1
                } else {
                    0
                }
            };
            if let Some(candidate) = single_candidate {
                return Some(*candidate);
            }
            //TODO Remove this during benchmark after testing
            assert!(bit >= 1);
        }
        // should never reach here
        None
    }
}

impl<T: ClientDB + Sized> ForkChoice for OptimisedLMDGhost<T> {
    fn add_block(
        &mut self,
        block: &BeaconBlock,
        block_hash: &Hash256,
    ) -> Result<(), ForkChoiceError> {
        // get the height of the parent
        let parent_height = self
            .block_store
            .get_reader(&block.parent_root)?
            .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(block.parent_root))?
            .slot()
            - GENESIS_SLOT;

        let parent_hash = &block.parent_root;

        // add the new block to the children of parent
        (*self
            .children
            .entry(block.parent_root)
            .or_insert_with(|| vec![]))
        .push(block_hash.clone());

        // build the ancestor data structure
        for index in 0..16 {
            if parent_height % (1 << index) == 0 {
                self.ancestors[index].insert(*block_hash, *parent_hash);
            } else {
                // TODO: This is unsafe. Will panic if parent_hash doesn't exist. Using it for debugging
                let parent_ancestor = self.ancestors[index][parent_hash];
                self.ancestors[index].insert(*block_hash, parent_ancestor);
            }
        }
        // update the max height
        self.max_known_height = std::cmp::max(self.max_known_height, parent_height + 1);
        Ok(())
    }

    fn add_attestation(
        &mut self,
        validator_index: u64,
        target_block_root: &Hash256,
    ) -> Result<(), ForkChoiceError> {
        // simply add the attestation to the latest_attestation_target
        self.latest_attestation_targets
            .insert(validator_index, target_block_root.clone());
        Ok(())
    }

    /// Perform lmd_ghost on the current chain to find the head.
    fn find_head(&mut self, justified_block_start: &Hash256) -> Result<Hash256, ForkChoiceError> {
        let block = self
            .block_store
            .get_reader(&justified_block_start)?
            .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*justified_block_start))?;
        //.into_beacon_block()?;

        let block_slot = block.slot();
        let block_height = block_slot - GENESIS_SLOT;
        let state_root = block.state_root();

        // get latest votes
        // Note: Votes are weighted by min(balance, MAX_DEPOSIT_AMOUNT) //
        // FORK_CHOICE_BALANCE_INCREMENT
        // build a hashmap of block_hash to weighted votes
        let mut latest_votes: HashMap<Hash256, u64> = HashMap::new();
        // gets the current weighted votes
        {
            let current_state = self
                .state_store
                .get_reader(&state_root)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconState(state_root))?
                .into_beacon_state()
                .ok_or_else(|| ForkChoiceError::IncorrectBeaconState(state_root))?;

            let active_validator_indices =
                get_active_validator_indices(&current_state.validator_registry, block_slot);

            for index in active_validator_indices {
                let balance =
                    std::cmp::min(current_state.validator_balances[index], MAX_DEPOSIT_AMOUNT)
                        / FORK_CHOICE_BALANCE_INCREMENT;
                if balance > 0 {
                    if let Some(target) = self.latest_attestation_targets.get(&(index as u64)) {
                        *latest_votes.entry(*target).or_insert_with(|| 0) += balance;
                    }
                }
            }
        }

        let mut current_head = *justified_block_start;

        // remove any votes that don't relate to our current head.
        latest_votes
            .retain(|hash, _| self.get_ancestor(*hash, block_height as u32) == Some(current_head));

        // begin searching for the head
        loop {
            // if there are no children, we are done, return the current_head
            let children = match self.children.get(&current_head) {
                Some(children) => children.clone(),
                None => return Ok(current_head),
            };

            // logarithmic lookup blocks to see if there are obvious winners, if so,
            // progress to the next iteration.
            let mut step = power_of_2_below(self.max_known_height as u32 - block_height as u32) / 2;
            while step > 0 {
                if let Some(clear_winner) = self.get_clear_winner(
                    &latest_votes,
                    block_height - (block_height % u64::from(step)) + u64::from(step),
                ) {
                    current_head = clear_winner;
                    break;
                }
                step /= 2;
            }
            if step > 0 {
            }
            // if our skip lookup failed and we only have one child, progress to that child
            else if children.len() == 1 {
                current_head = children[0];
            }
            // we need to find the best child path to progress down.
            else {
                let mut child_votes = HashMap::new();
                for (voted_hash, vote) in latest_votes.iter() {
                    // if the latest votes correspond to a child
                    if let Some(child) = self.get_ancestor(*voted_hash, (block_height + 1) as u32) {
                        // add up the votes for each child
                        *child_votes.entry(child).or_insert_with(|| 0) += vote;
                    }
                }
                // given the votes on the children, find the best child
                current_head = self
                    .choose_best_child(&child_votes)
                    .ok_or(ForkChoiceError::CannotFindBestChild)?;
            }

            // No head was found, re-iterate

            // update the block height for the next iteration
            let block_height = self
                .block_store
                .get_reader(&current_head)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*justified_block_start))?
                .slot()
                - GENESIS_SLOT;

            // prune the latest votes for votes that are not part of current chosen chain
            // more specifically, only keep votes that have head as an ancestor
            latest_votes.retain(|hash, _| {
                self.get_ancestor(*hash, block_height as u32) == Some(current_head)
            });
        }
    }
}

/// Type for storing blocks in a memory cache. Key is comprised of block-hash plus the height.
#[derive(PartialEq, Eq, Hash)]
pub struct CacheKey<T> {
    block_hash: Hash256,
    block_height: T,
}

impl<T> CacheKey<T> {
    pub fn new(block_hash: &Hash256, block_height: T) -> Self {
        CacheKey {
            block_hash: *block_hash,
            block_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_power_of_2_below() {
        println!("{:?}", std::f32::MAX);
        assert_eq!(power_of_2_below(4), 4);
        assert_eq!(power_of_2_below(5), 4);
        assert_eq!(power_of_2_below(7), 4);
        assert_eq!(power_of_2_below(24), 16);
        assert_eq!(power_of_2_below(32), 32);
        assert_eq!(power_of_2_below(33), 32);
        assert_eq!(power_of_2_below(63), 32);
    }
}
