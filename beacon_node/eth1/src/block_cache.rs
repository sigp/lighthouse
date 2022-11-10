use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::ops::RangeInclusive;

pub use eth2::lighthouse::Eth1Block;
use eth2::types::Hash256;
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The timestamp of each block equal to or later than the block prior to it.
    InconsistentTimestamp { parent: u64, child: u64 },
    /// Some `Eth1Block` was provided with the same block number but different data. The source
    /// of eth1 data is inconsistent.
    Conflicting(u64),
    /// The given block was not one block number higher than the higest known block number.
    NonConsecutive { given: u64, expected: u64 },
    /// Some invariant was violated, there is a likely bug in the code.
    Internal(String),
}

/// Stores block and deposit contract information and provides queries based upon the block
/// timestamp.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct BlockCache {
    blocks: Vec<Arc<Eth1Block>>,
    #[ssz(skip_serializing, skip_deserializing)]
    by_hash: HashMap<Hash256, Arc<Eth1Block>>,
}

impl BlockCache {
    /// Returns the number of blocks stored in `self`.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// True if the cache does not store any blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the earliest (lowest timestamp) block, if any.
    pub fn earliest_block(&self) -> Option<&Eth1Block> {
        self.blocks.first().map(|ptr| ptr.as_ref())
    }

    /// Returns the latest (highest timestamp) block, if any.
    pub fn latest_block(&self) -> Option<&Eth1Block> {
        self.blocks.last().map(|ptr| ptr.as_ref())
    }

    /// Returns the timestamp of the earliest block in the cache (if any).
    pub fn earliest_block_timestamp(&self) -> Option<u64> {
        self.blocks.first().map(|block| block.timestamp)
    }

    /// Returns the timestamp of the latest block in the cache (if any).
    pub fn latest_block_timestamp(&self) -> Option<u64> {
        self.blocks.last().map(|block| block.timestamp)
    }

    /// Returns the lowest block number stored.
    pub fn lowest_block_number(&self) -> Option<u64> {
        self.blocks.first().map(|block| block.number)
    }

    /// Returns the highest block number stored.
    pub fn highest_block_number(&self) -> Option<u64> {
        self.blocks.last().map(|block| block.number)
    }

    /// Returns an iterator over all blocks.
    ///
    /// Blocks a guaranteed to be returned with;
    ///
    /// - Monotonically increasing block numbers.
    /// - Non-uniformly increasing block timestamps.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Eth1Block> + Clone {
        self.blocks.iter().map(|ptr| ptr.as_ref())
    }

    /// Shortens the cache, keeping the latest (by block number) `len` blocks while dropping the
    /// rest.
    ///
    /// If `len` is greater than the vector's current length, this has no effect.
    pub fn truncate(&mut self, len: usize) {
        if len < self.blocks.len() {
            let remaining = self.blocks.split_off(self.blocks.len() - len);
            for block in &self.blocks {
                self.by_hash.remove(&block.hash);
            }
            self.blocks = remaining;
        }
    }

    /// Returns the range of block numbers stored in the block cache. All blocks in this range can
    /// be accessed.
    fn available_block_numbers(&self) -> Option<RangeInclusive<u64>> {
        Some(self.blocks.first()?.number..=self.blocks.last()?.number)
    }

    /// Returns a block with the corresponding number, if any.
    pub fn block_by_number(&self, block_number: u64) -> Option<&Eth1Block> {
        self.blocks
            .get(
                self.blocks
                    .as_slice()
                    .binary_search_by(|block| block.number.cmp(&block_number))
                    .ok()?,
            )
            .map(|ptr| ptr.as_ref())
    }

    /// Returns a block with the corresponding hash, if any.
    pub fn block_by_hash(&self, block_hash: &Hash256) -> Option<&Eth1Block> {
        self.by_hash.get(block_hash).map(|ptr| ptr.as_ref())
    }

    /// Rebuilds the by_hash map
    pub fn rebuild_by_hash_map(&mut self) {
        self.by_hash.clear();
        for block in self.blocks.iter() {
            self.by_hash.insert(block.hash, block.clone());
        }
    }

    /// Insert an `Eth1Snapshot` into `self`, allowing future queries.
    ///
    /// Allows inserting either:
    ///
    /// - The root block (i.e., any block if there are no existing blocks), or,
    /// - An immediate child of the most recent (highest block number) block.
    ///
    /// ## Errors
    ///
    /// - If the cache is not empty and `item.block.block_number - 1` is not already in `self`.
    /// - If `item.block.block_number` is in `self`, but is not identical to the supplied
    /// `Eth1Snapshot`.
    /// - If `item.block.timestamp` is prior to the parent.
    pub fn insert_root_or_child(&mut self, block: Eth1Block) -> Result<(), Error> {
        let expected_block_number = self
            .highest_block_number()
            .map(|n| n + 1)
            .unwrap_or_else(|| block.number);

        // If there are already some cached blocks, check to see if the new block number is one of
        // them.
        //
        // If the block is already known, check to see the given block is identical to it. If not,
        // raise an inconsistency error. This is mostly likely caused by some fork on the eth1
        // chain.
        if let Some(local) = self.available_block_numbers() {
            if local.contains(&block.number) {
                let known_block = self.block_by_number(block.number).ok_or_else(|| {
                    Error::Internal("An expected block was not present".to_string())
                })?;

                if known_block == &block {
                    return Ok(());
                } else {
                    return Err(Error::Conflicting(block.number));
                };
            }
        }

        // Only permit blocks when it's either:
        //
        // - The first block inserted.
        // - Exactly one block number higher than the highest known block number.
        if block.number != expected_block_number {
            return Err(Error::NonConsecutive {
                given: block.number,
                expected: expected_block_number,
            });
        }

        // If the block is not the first block inserted, ensure that its timestamp is not higher
        // than its parents.
        if let Some(previous_block) = self.blocks.last() {
            if previous_block.timestamp > block.timestamp {
                return Err(Error::InconsistentTimestamp {
                    parent: previous_block.timestamp,
                    child: block.timestamp,
                });
            }
        }

        let ptr = Arc::new(block);
        self.by_hash.insert(ptr.hash, ptr.clone());
        self.blocks.push(ptr);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    fn get_block(i: u64, interval_secs: u64) -> Eth1Block {
        Eth1Block {
            hash: Hash256::from_low_u64_be(i),
            timestamp: i * interval_secs,
            number: i,
            deposit_root: Some(Hash256::from_low_u64_be(i << 32)),
            deposit_count: Some(i),
        }
    }

    fn get_blocks(n: usize, interval_secs: u64) -> Vec<Eth1Block> {
        (0..n as u64).map(|i| get_block(i, interval_secs)).collect()
    }

    fn insert(cache: &mut BlockCache, s: Eth1Block) -> Result<(), Error> {
        cache.insert_root_or_child(s)
    }

    #[test]
    fn truncate() {
        let n = 16;
        let blocks = get_blocks(n, 10);

        let mut cache = BlockCache::default();

        for block in blocks {
            insert(&mut cache, block.clone()).expect("should add consecutive blocks");
        }

        for len in &[0, 1, 2, 3, 4, 8, 15, 16] {
            let mut cache = cache.clone();

            cache.truncate(*len);

            assert_eq!(
                cache.blocks.len(),
                *len,
                "should truncate to length: {}",
                *len
            );
        }

        let mut cache_2 = cache;
        cache_2.truncate(17);
        assert_eq!(
            cache_2.blocks.len(),
            n,
            "truncate to larger than n should be a no-op"
        );
    }

    #[test]
    fn inserts() {
        let n = 16;
        let blocks = get_blocks(n, 10);

        let mut cache = BlockCache::default();

        for block in blocks {
            insert(&mut cache, block.clone()).expect("should add consecutive blocks");
        }

        // No error for re-adding a block identical to one that exists.
        assert!(insert(&mut cache, get_block(n as u64 - 1, 10)).is_ok());

        // Error for re-adding a block that is different to the one that exists.
        assert!(insert(&mut cache, get_block(n as u64 - 1, 11)).is_err());

        // Error for adding non-consecutive blocks.
        assert!(insert(&mut cache, get_block(n as u64 + 1, 10)).is_err());
        assert!(insert(&mut cache, get_block(n as u64 + 2, 10)).is_err());

        // Error for adding timestamp prior to previous.
        assert!(insert(&mut cache, get_block(n as u64, 1)).is_err());
        // Double check to make sure previous test was only affected by timestamp.
        assert!(insert(&mut cache, get_block(n as u64, 10)).is_ok());
    }

    #[test]
    fn duplicate_timestamp() {
        let mut blocks = get_blocks(7, 10);

        blocks[0].timestamp = 0;
        blocks[1].timestamp = 10;
        blocks[2].timestamp = 10;
        blocks[3].timestamp = 20;
        blocks[4].timestamp = 30;
        blocks[5].timestamp = 40;
        blocks[6].timestamp = 40;

        let mut cache = BlockCache::default();

        for block in &blocks {
            insert(&mut cache, block.clone())
                .expect("should add consecutive blocks with duplicate timestamps");
        }

        let blocks = blocks.into_iter().map(Arc::new).collect::<Vec<_>>();

        assert_eq!(cache.blocks, blocks, "should have added all blocks");
    }
}
