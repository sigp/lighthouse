//! The optimised bitwise LMD-GHOST fork choice rule.
extern crate bit_vec;

use crate::{ForkChoice, ForkChoiceError};
use bit_vec::BitVec;
use db::Store;
use log::{debug, trace};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256, Slot, SlotHeight};

//TODO: Pruning - Children
//TODO: Handle Syncing

// NOTE: This uses u32 to represent difference between block heights. Thus this is only
// applicable for block height differences in the range of a u32.
// This can potentially be parallelized in some parts.

/// Compute the base-2 logarithm of an integer, floored (rounded down)
#[inline]
fn log2_int(x: u64) -> u32 {
    if x == 0 {
        return 0;
    }
    63 - x.leading_zeros()
}

fn power_of_2_below(x: u64) -> u64 {
    2u64.pow(log2_int(x))
}

/// Stores the necessary data structures to run the optimised bitwise lmd ghost algorithm.
pub struct BitwiseLMDGhost<T, E> {
    /// A cache of known ancestors at given heights for a specific block.
    //TODO: Consider FnvHashMap
    cache: HashMap<CacheKey<u64>, Hash256>,
    /// Log lookup table for blocks to their ancestors.
    //TODO: Verify we only want/need a size 16 log lookup
    ancestors: Vec<HashMap<Hash256, Hash256>>,
    /// Stores the children for any given parent.
    children: HashMap<Hash256, Vec<Hash256>>,
    /// The latest attestation targets as a map of validator index to block hash.
    //TODO: Could this be a fixed size vec
    latest_attestation_targets: HashMap<u64, Hash256>,
    /// Block and state storage.
    store: Arc<T>,
    max_known_height: SlotHeight,
    _phantom: PhantomData<E>,
}

impl<T: Store, E: EthSpec> BitwiseLMDGhost<T, E> {
    pub fn new(store: Arc<T>) -> Self {
        BitwiseLMDGhost {
            cache: HashMap::new(),
            ancestors: vec![HashMap::new(); 16],
            latest_attestation_targets: HashMap::new(),
            children: HashMap::new(),
            max_known_height: SlotHeight::new(0),
            store,
            _phantom: PhantomData,
        }
    }

    /// Finds the latest votes weighted by validator balance. Returns a hashmap of block_hash to
    /// weighted votes.
    pub fn get_latest_votes(
        &self,
        state_root: &Hash256,
        block_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<HashMap<Hash256, u64>, ForkChoiceError> {
        // get latest votes
        // Note: Votes are weighted by min(balance, MAX_DEPOSIT_AMOUNT) //
        // FORK_CHOICE_BALANCE_INCREMENT
        // build a hashmap of block_hash to weighted votes
        let mut latest_votes: HashMap<Hash256, u64> = HashMap::new();
        // gets the current weighted votes
        let current_state: BeaconState<E> = self
            .store
            .get(&state_root)?
            .ok_or_else(|| ForkChoiceError::MissingBeaconState(*state_root))?;

        let active_validator_indices =
            current_state.get_active_validator_indices(block_slot.epoch(spec.slots_per_epoch));

        for index in active_validator_indices {
            let balance = std::cmp::min(
                current_state.validator_balances[index],
                spec.max_deposit_amount,
            ) / spec.fork_choice_balance_increment;
            if balance > 0 {
                if let Some(target) = self.latest_attestation_targets.get(&(index as u64)) {
                    *latest_votes.entry(*target).or_insert_with(|| 0) += balance;
                }
            }
        }
        trace!("Latest votes: {:?}", latest_votes);
        Ok(latest_votes)
    }

    /// Gets the ancestor at a given height `at_height` of a block specified by `block_hash`.
    fn get_ancestor(
        &mut self,
        block_hash: Hash256,
        target_height: SlotHeight,
        spec: &ChainSpec,
    ) -> Option<Hash256> {
        // return None if we can't get the block from the db.
        let block_height = {
            let block_slot = self
                .store
                .get::<BeaconBlock>(&block_hash)
                .ok()?
                .expect("Should have returned already if None")
                .slot;

            block_slot.height(spec.genesis_slot)
        };

        // verify we haven't exceeded the block height
        if target_height >= block_height {
            if target_height > block_height {
                return None;
            } else {
                return Some(block_hash);
            }
        }
        // check if the result is stored in our cache
        let cache_key = CacheKey::new(&block_hash, target_height.as_u64());
        if let Some(ancestor) = self.cache.get(&cache_key) {
            return Some(*ancestor);
        }

        // not in the cache recursively search for ancestors using a log-lookup
        if let Some(ancestor) = {
            let ancestor_lookup = self.ancestors
                [log2_int((block_height - target_height - 1u64).as_u64()) as usize]
                .get(&block_hash)
                //TODO: Panic if we can't lookup and fork choice fails
                .expect("All blocks should be added to the ancestor log lookup table");
            self.get_ancestor(*ancestor_lookup, target_height, &spec)
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
        block_height: SlotHeight,
        spec: &ChainSpec,
    ) -> Option<Hash256> {
        // map of vote counts for every hash at this height
        let mut current_votes: HashMap<Hash256, u64> = HashMap::new();
        let mut total_vote_count = 0;

        trace!("Clear winner at block height: {}", block_height);
        // loop through the latest votes and count all votes
        // these have already been weighted by balance
        for (hash, votes) in latest_votes.iter() {
            if let Some(ancestor) = self.get_ancestor(*hash, block_height, spec) {
                let current_vote_value = current_votes.get(&ancestor).unwrap_or_else(|| &0);
                current_votes.insert(ancestor, current_vote_value + *votes);
                total_vote_count += votes;
            }
        }
        // Check if there is a clear block winner at this height. If so return it.
        for (hash, votes) in current_votes.iter() {
            if *votes > total_vote_count / 2 {
                // we have a clear winner, return it
                return Some(*hash);
            }
        }
        // didn't find a clear winner
        None
    }

    // Finds the best child, splitting children into a binary tree, based on their hashes (Bitwise
    // LMD Ghost)
    fn choose_best_child(&self, votes: &HashMap<Hash256, u64>) -> Option<Hash256> {
        if votes.is_empty() {
            return None;
        }
        let mut bitmask: BitVec = BitVec::new();
        // loop through all bits
        for bit in 0..=256 {
            let mut zero_votes = 0;
            let mut one_votes = 0;
            let mut single_candidate = (None, false);

            trace!("Child vote length: {}", votes.len());
            for (candidate, votes) in votes.iter() {
                let candidate_bit: BitVec = BitVec::from_bytes(candidate.as_bytes());

                // if the bitmasks don't match, exclude candidate
                if !bitmask.iter().eq(candidate_bit.iter().take(bit)) {
                    trace!(
                        "Child: {} was removed in bit: {} with the bitmask: {:?}",
                        candidate,
                        bit,
                        bitmask
                    );
                    continue;
                }
                if candidate_bit.get(bit) == Some(false) {
                    zero_votes += votes;
                } else {
                    one_votes += votes;
                }

                if single_candidate.0.is_none() {
                    single_candidate.0 = Some(candidate);
                    single_candidate.1 = true;
                } else {
                    single_candidate.1 = false;
                }
            }
            bitmask.push(one_votes > zero_votes);
            if single_candidate.1 {
                return Some(*single_candidate.0.expect("Cannot reach this"));
            }
        }
        // should never reach here
        None
    }
}

impl<T: Store, E: EthSpec> ForkChoice for BitwiseLMDGhost<T, E> {
    fn add_block(
        &mut self,
        block: &BeaconBlock,
        block_hash: &Hash256,
        spec: &ChainSpec,
    ) -> Result<(), ForkChoiceError> {
        // get the height of the parent
        let parent_height = self
            .store
            .get::<BeaconBlock>(&block.previous_block_root)?
            .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(block.previous_block_root))?
            .slot
            .height(spec.genesis_slot);

        let parent_hash = &block.previous_block_root;

        // add the new block to the children of parent
        (*self
            .children
            .entry(block.previous_block_root)
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
        spec: &ChainSpec,
    ) -> Result<(), ForkChoiceError> {
        // simply add the attestation to the latest_attestation_target if the block_height is
        // larger
        trace!(
            "Adding attestation of validator: {:?} for block: {}",
            validator_index,
            target_block_root
        );
        let attestation_target = self
            .latest_attestation_targets
            .entry(validator_index)
            .or_insert_with(|| *target_block_root);
        // if we already have a value
        if attestation_target != target_block_root {
            trace!("Old attestation found: {:?}", attestation_target);
            // get the height of the target block
            let block_height = self
                .store
                .get::<BeaconBlock>(&target_block_root)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*target_block_root))?
                .slot
                .height(spec.genesis_slot);

            // get the height of the past target block
            let past_block_height = self
                .store
                .get::<BeaconBlock>(&attestation_target)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*attestation_target))?
                .slot
                .height(spec.genesis_slot);
            // update the attestation only if the new target is higher
            if past_block_height < block_height {
                trace!("Updating old attestation");
                *attestation_target = *target_block_root;
            }
        }
        Ok(())
    }

    /// Perform lmd_ghost on the current chain to find the head.
    fn find_head(
        &mut self,
        justified_block_start: &Hash256,
        spec: &ChainSpec,
    ) -> Result<Hash256, ForkChoiceError> {
        debug!(
            "Starting optimised fork choice at block: {}",
            justified_block_start
        );
        let block = self
            .store
            .get::<BeaconBlock>(&justified_block_start)?
            .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*justified_block_start))?;

        let block_slot = block.slot;
        let state_root = block.state_root;
        let mut block_height = block_slot.height(spec.genesis_slot);

        let mut current_head = *justified_block_start;

        let mut latest_votes = self.get_latest_votes(&state_root, block_slot, spec)?;

        // remove any votes that don't relate to our current head.
        latest_votes
            .retain(|hash, _| self.get_ancestor(*hash, block_height, spec) == Some(current_head));

        // begin searching for the head
        loop {
            debug!(
                "Iteration for block: {} with vote length: {}",
                current_head,
                latest_votes.len()
            );
            // if there are no children, we are done, return the current_head
            let children = match self.children.get(&current_head) {
                Some(children) => children.clone(),
                None => {
                    debug!("Head found: {}", current_head);
                    return Ok(current_head);
                }
            };

            // logarithmic lookup blocks to see if there are obvious winners, if so,
            // progress to the next iteration.
            let mut step =
                power_of_2_below(self.max_known_height.saturating_sub(block_height).as_u64()) / 2;
            while step > 0 {
                trace!("Current Step: {}", step);
                if let Some(clear_winner) = self.get_clear_winner(
                    &latest_votes,
                    block_height - (block_height % step) + step,
                    spec,
                ) {
                    current_head = clear_winner;
                    break;
                }
                step /= 2;
            }
            if step > 0 {
                trace!("Found clear winner: {}", current_head);
            }
            // if our skip lookup failed and we only have one child, progress to that child
            else if children.len() == 1 {
                current_head = children[0];
                trace!(
                    "Lookup failed, only one child, proceeding to child: {}",
                    current_head
                );
            }
            // we need to find the best child path to progress down.
            else {
                trace!("Searching for best child");
                let mut child_votes = HashMap::new();
                for (voted_hash, vote) in latest_votes.iter() {
                    // if the latest votes correspond to a child
                    if let Some(child) = self.get_ancestor(*voted_hash, block_height + 1, spec) {
                        // add up the votes for each child
                        *child_votes.entry(child).or_insert_with(|| 0) += vote;
                    }
                }
                // check if we have votes of children, if not select the smallest hash child
                if child_votes.is_empty() {
                    current_head = *children
                        .iter()
                        .min_by(|child1, child2| child1.cmp(child2))
                        .expect("Must be children here");
                    trace!(
                        "Children have no votes - smallest hash chosen: {}",
                        current_head
                    );
                } else {
                    // given the votes on the children, find the best child
                    current_head = self
                        .choose_best_child(&child_votes)
                        .ok_or(ForkChoiceError::CannotFindBestChild)?;
                    trace!("Best child found: {}", current_head);
                }
            }

            // didn't find head yet, proceed to next iteration
            // update block height
            block_height = self
                .store
                .get::<BeaconBlock>(&current_head)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(current_head))?
                .slot
                .height(spec.genesis_slot);
            // prune the latest votes for votes that are not part of current chosen chain
            // more specifically, only keep votes that have head as an ancestor
            for hash in latest_votes.keys() {
                trace!(
                    "Ancestor for vote: {} at height: {} is: {:?}",
                    hash,
                    block_height,
                    self.get_ancestor(*hash, block_height, spec)
                );
            }
            latest_votes.retain(|hash, _| {
                self.get_ancestor(*hash, block_height, spec) == Some(current_head)
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
        assert_eq!(power_of_2_below(4), 4);
        assert_eq!(power_of_2_below(5), 4);
        assert_eq!(power_of_2_below(7), 4);
        assert_eq!(power_of_2_below(24), 16);
        assert_eq!(power_of_2_below(32), 32);
        assert_eq!(power_of_2_below(33), 32);
        assert_eq!(power_of_2_below(63), 32);
    }

    #[test]
    pub fn test_power_of_2_below_large() {
        let pow: u64 = 1 << 24;
        for x in (pow - 20)..(pow + 20) {
            assert!(power_of_2_below(x) <= x, "{}", x);
        }
    }
}
