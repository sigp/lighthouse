extern crate byteorder;
extern crate fast_math;
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
    Attestation, Hash256,
};

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
    /// Block storage access.
    block_store: Arc<BeaconBlockStore<T>>,
    /// State storage access.
    state_store: Arc<BeaconStateStore<T>>,
    /// Genesis slot height to calculate block heights.
    GENESIS_SLOT: u64,
}

impl<T> OptimisedLMDGhost<T>
where
    T: ClientDB + Sized,
{
    pub fn new(block_store: BeaconBlockStore<T>, state_store: BeaconStateStore<T>) -> Self {
        OptimisedLMDGhost {
            cache: HashMap::new(),
            ancestors: vec![HashMap::new(); 16],
            block_store: Arc::new(block_store),
            state_store: Arc::new(state_store),
            GENESIS_SLOT: 0,
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
                .unwrap()
                .into_beacon_block()?
                .slot;

            (block_slot - self.GENESIS_SLOT) as u32
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

    fn get_clear_winner(
        &mut self,
        latest_votes: HashMap<Hash256, usize>,
        h: usize,
    ) -> Option<Hash256> {
        let mut at_height: HashMap<Hash256, usize> = HashMap::new();
        let mut total_vote_count = 0;

        for (hash, votes) in latest_votes.iter() {
            if let Some(ancestor) = self.get_ancestor(*hash, h as u32) {
                let at_height_value = at_height.get(&ancestor).unwrap_or_else(|| &0);
                at_height.insert(ancestor, at_height_value + *votes);
                total_vote_count += votes;
            }
        }
        for (hash, votes) in at_height.iter() {
            if *votes >= total_vote_count / 2 {
                return Some(*hash);
            }
        }
        None
    }

    fn choose_best_child(&self, votes: &HashMap<Hash256, usize>) -> Option<Hash256> {
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
        None
    }

    // Implement ForkChoice to build required data structures during block processing.
}

/// Defines the interface for Fork Choices. Each Fork choice will define their own data structures
/// which can be built in block processing through the `add_block` and `add_attestation` functions.
/// The main fork choice algorithm is specified in `find_head`.
pub trait ForkChoice {
    /// Called when a block has been added. Allows generic block-level data structures to be
    /// built for a given fork-choice.
    fn add_block(&self, block: Hash256);
    /// Called when an attestation has been added. Allows generic attestation-level data structures to be built for a given fork choice.
    fn add_attestation(&self, attestation: Attestation);
    /// The fork-choice algorithm to find the current canonical head of the chain.
    fn find_head() -> Hash256;
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
