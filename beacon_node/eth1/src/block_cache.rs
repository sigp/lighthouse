use std::ops::RangeInclusive;
use types::{Eth1Data, Hash256};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The timestamp of each block **must** be higher than the block prior to it.
    InconsistentTimestamp { parent: u64, child: u64 },
    /// There is no block prior to the given `target_secs`, unable to complete request.
    NoBlockForTarget {
        target_secs: u64,
        known_blocks: usize,
    },
    /// Some `Eth1Block` was provided with the same block number but different data. The source
    /// of eth1 data is inconsistent.
    Conflicting(u64),
    /// The given block was not one block number higher than the higest known block number.
    NonConsecutive { given: u64, expected: u64 },
    /// The given block number is too large to fit in a usize.
    BlockNumberTooLarge(u64),
    /// Some invariant was violated, there is a likely bug in the code.
    Internal(String),
}

/// A block of the eth1 chain.
///
/// Contains all information required to add a `BlockCache` entry.
#[derive(Debug, PartialEq, Clone)]
pub struct Eth1Block {
    pub hash: Hash256,
    pub timestamp: u64,
    pub number: u64,
    pub deposit_root: Option<Hash256>,
    pub deposit_count: Option<u64>,
}

impl Eth1Block {
    pub fn eth1_data(self) -> Option<Eth1Data> {
        Some(Eth1Data {
            deposit_root: self.deposit_root?,
            deposit_count: self.deposit_count?,
            block_hash: self.hash,
        })
    }
}

/// Stores block and deposit contract information and provides queries based upon the block
/// timestamp.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct BlockCache {
    blocks: Vec<Eth1Block>,
}

impl BlockCache {
    /// Returns the number of blocks stored in `self`.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the highest block number stored.
    pub fn highest_block_number(&self) -> Option<u64> {
        self.blocks.last().map(|block| block.number)
    }

    /// Returns an iterator over all blocks.
    ///
    /// Blocks will be returned with:
    ///
    /// - Monotically increase block numbers.
    /// - Non-uniformly increasing block timestamps.
    pub fn iter(&self) -> impl Iterator<Item = &Eth1Block> {
        self.blocks.iter()
    }

    /// Shortens the cache, keeping the latest `len` blocks and dropping the rest.
    ///
    /// If `len` is greater than the vector's current length, this has no effect.
    ///
    /// Providing `len == 0` is a no-op.
    pub fn truncate(&mut self, len: usize) {
        if (len != 0) && len < self.blocks.len() {
            self.blocks = self.blocks.split_off(self.blocks.len() - len);
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
            .get(self.block_index_by_block_number(block_number)?)
    }

    /// Returns a block with the corresponding number, if any.
    fn block_index_by_block_number(&self, target: u64) -> Option<usize> {
        self.blocks
            .as_slice()
            .binary_search_by(|block| block.number.cmp(&target))
            .ok()
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
        // - Exactly only block number higher than the highest known block number.
        if block.number != expected_block_number {
            return Err(Error::NonConsecutive {
                given: block.number,
                expected: expected_block_number,
            });
        }

        // If the block is not the first block inserted, ensure that it's timestamp is not higher
        // than it's parents.
        if let Some(previous_block) = self.blocks.last() {
            if previous_block.timestamp > block.timestamp {
                return Err(Error::InconsistentTimestamp {
                    parent: previous_block.timestamp,
                    child: block.timestamp,
                });
            }
        }

        self.blocks.push(block);

        Ok(())
    }

    /*
    /// Returns the range of block numbers stored in the block cache. All blocks in this range can
    /// be accessed.
    pub fn available_block_numbers(&self) -> Option<RangeInclusive<u64>> {
        Some(self.blocks.first()?.block_number..=self.blocks.last()?.block.number)
    }

    /// Returns the block number one higher than the highest currently stored.
    ///
    /// Returns `0` if there are no blocks stored.
    pub fn next_block_number(&self) -> u64 {
        (self.offset + self.blocks.len()) as u64
    }

    /// Fetches an `Eth1Block` by block number.
    fn get(&self, block_number: u64) -> Option<&Eth1Block> {
        let i = usize::try_from(block_number)
            .ok()?
            .checked_sub(self.offset)?;
        self.blocks.get(i)
    }

    /// Returns the index of the first `Eth1Block` that is lower than the given `target` time
    /// (assumed to be duration since unix epoch), if any.
    ///
    /// If there are blocks with duplicate timestamps, the block with the highest number is
    /// preferred.
    fn index_at_time(&self, target: Duration) -> Option<usize> {
        let search = self.blocks.as_slice().binary_search_by(|block| {
            Duration::from_secs(block.block.timestamp).cmp(&target)
        });

        let index = match search {
            // If an exact match for this duration was found, search forward trying to find the
            // block with the highest number that has this the same timestamp.
            //
            // This handles the case where blocks have matching timestamps. Whilst this _shouldn't_
            // be possible in mainnet ethereum, it has been seen when testing with ganache.
            Ok(mut i) => loop {
                match self.blocks.get(i + 1) {
                    Some(next) if Duration::from_secs(next.block.timestamp) == target => i += 1,
                    None | Some(_) => break i,
                }
            },
            Err(i) => i.saturating_sub(1),
        };

        let block = self.blocks.get(index)?;

        if Duration::from_secs(block.block.timestamp) <= target {
            Some(index)
        } else {
            None
        }
    }

    /// Returns the first `Eth1Data` from a block with a timestamp that is lower than `target`.
    ///
    /// In other words, returns the `Eth1Data` that was canonical at the given `target`.
    ///
    /// Assumes `target` is a duration since unix epoch.
    pub fn eth1_data_at_time(&self, target: Duration) -> Option<Eth1Data> {
        self.blocks
            .get(self.index_at_time(target)?)
            .cloned()
            .map(Into::into)
    }

    /// Like `Self::eth1_data_at_time(..)`, except also returns **at most** `max_count` number of
    /// ancestor `Eth1Data` values.
    ///
    /// In other words, returns a consecutive range of `Eth1Data`, all prior to `target`.
    ///
    /// Assumes `target` is a duration since unix epoch.
    pub fn get_eth1_data_ancestors(
        &self,
        target: Duration,
        max_count: usize,
    ) -> Result<Vec<Eth1Data>, Error> {
        if max_count == 0 {
            Ok(vec![])
        } else {
            let last = self
                .index_at_time(target)
                .ok_or_else(|| Error::NoBlockForTarget {
                    target_secs: target.as_secs(),
                    known_blocks: self.blocks.len(),
                })?;
            let first = last.saturating_sub(max_count.saturating_sub(1));

            self.blocks
                .get(first..=last)
                .ok_or_else(|| Error::Internal("Inconsistent items length".into()))
                .map(|items| items.into_iter().cloned().map(Into::into).collect())
        }
    }
    */
}

#[cfg(test)]
mod tests {
    use super::*;

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
        (0..n as u64)
            .into_iter()
            .map(|i| get_block(i, interval_secs))
            .collect()
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

        for len in vec![1, 2, 3, 4, 8, 15, 16] {
            let mut cache = cache.clone();

            cache.truncate(len);

            assert_eq!(
                cache.blocks.len(),
                len,
                "should truncate to length: {}",
                len
            );
        }

        let mut cache_2 = cache.clone();
        cache_2.truncate(0);
        assert_eq!(cache_2.blocks.len(), n, "truncate to 0 should be a no-op");

        let mut cache_2 = cache.clone();
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
    }

    /*
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
            insert(&mut cache, block.clone()).expect("should add consecutive blocks");
        }

        // Ensures that the given `target` finds the snapsnot at `blocks[i]`.
        let do_test = |target, i: usize| {
            assert_eq!(
                cache.get_eth1_data_ancestors(target, 1),
                Ok(vec![blocks[i].clone().into()]),
                "should find block {} for timestamp {}",
                i,
                target.as_secs()
            );
        };

        do_test(Duration::from_secs(0), 0);
        do_test(Duration::from_secs(10), 2);
        do_test(Duration::from_secs(20), 3);
        do_test(Duration::from_secs(30), 4);
        do_test(Duration::from_secs(40), 6);
    }
    */

    /*
    #[test]
    fn block_at_time_valid() {
        let n = 16;
        let duration = 10;
        let blocks = get_blocks(n, duration);

        let mut cache = BlockCache::default();

        for block in blocks {
            insert(&mut cache, block.clone()).expect("should add consecutive blocks");
        }

        for i in 0..n as u64 {
            // Should find exact match when times match.
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs(i * duration)),
                Some(get_block(i, 10).into()),
                "should find eth1 data with exact time for {}",
                i
            );

            // Should find prior when searching between times (low duration).
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs(i * duration + 1)),
                Some(get_block(i, 10).into()),
                "should find prior low eth1 data when searching between durations for  {}",
                i
            );

            // Should find prior when searching between times (high duration).
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs((i + 1) * duration - 1)),
                Some(get_block(i, 10).into()),
                "should find prior high eth1 data when searching between durations for  {}",
                i
            );
        }
    }

    #[test]
    fn block_at_time_invalid() {
        let x = 2;
        let duration = 10;

        let mut cache = BlockCache::new(0);

        // Should return none on empty cache.
        assert!(cache.eth1_data_at_time(Duration::from_secs(x)).is_none());

        insert(&mut cache, get_block(x, duration)).expect("should add first block");

        // Should return none for prior time.
        assert!(cache
            .eth1_data_at_time(Duration::from_secs((x - 1) * duration))
            .is_none());
    }

    #[test]
    fn block_ancestors_valid() {
        let n = 16;
        let duration = 10;
        let blocks = get_blocks(n, duration);

        let mut cache = BlockCache::new(0);

        for block in &blocks {
            insert(&mut cache, block.clone()).expect("should add consecutive blocks");
        }

        for i in 0..n as u64 {
            for max_count in 0..i as usize {
                let ancestors: Vec<Eth1Data> = blocks[0..=i as usize]
                    .iter()
                    .rev()
                    .take(max_count)
                    .rev()
                    .cloned()
                    .map(Into::into)
                    .collect();

                assert_eq!(ancestors.len(), max_count);

                // Exact time.
                assert_eq!(
                    cache.get_eth1_data_ancestors(Duration::from_secs(i * duration), max_count),
                    Ok(ancestors.clone()),
                    "should find ancestors for i: {}, max_count: {}, scenario: exact",
                    i,
                    max_count
                );

                // Time above by large margin.
                assert_eq!(
                    cache.get_eth1_data_ancestors(
                        Duration::from_secs((i + 1) * duration - 1),
                        max_count
                    ),
                    Ok(ancestors.clone()),
                    "should find ancestors for {} small duration",
                    i
                );

                // Time above by small margin.
                assert_eq!(
                    cache.get_eth1_data_ancestors(Duration::from_secs(i * duration + 1), max_count),
                    Ok(ancestors.clone()),
                    "should find ancestors for {} large duration",
                    i
                );
            }
        }
    }

    #[test]
    fn block_ancestors_invalid() {
        let x = 2;
        let duration = 10;

        let mut cache = BlockCache::new(0);

        // Should return error on empty cache.
        assert!(cache
            .get_eth1_data_ancestors(Duration::from_secs(x), 1)
            .is_err());

        insert(&mut cache, get_block(x, duration)).expect("should add first block");

        // Should return error for prior time.
        assert!(cache
            .get_eth1_data_ancestors(Duration::from_secs((x - 1) * duration), 1)
            .is_err());
    }
    */
}
