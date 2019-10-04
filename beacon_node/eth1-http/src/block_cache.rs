use crate::http::Block;
use std::convert::TryFrom;
use std::ops::RangeInclusive;
use std::time::Duration;
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
    /// Some `Eth1Snapshot` was provided with the same block number but different data. The source
    /// of eth1 data is inconsistent.
    Conflicting(u64),
    /// The given snapshot was not one block number higher than the higest known block number.
    NonConsecutive { given: u64, expected: u64 },
    /// The given block number is too large to fit in a usize.
    BlockNumberTooLarge(u64),
    /// Some invariant was violated, there is a likely bug in the code.
    Internal(String),
}

/// A snapshot of the eth1 chain.
///
/// Contains all information required to add a `BlockCache` entry.
#[derive(Debug, PartialEq, Clone)]
struct Eth1Snapshot {
    pub block: Block,
    pub deposit_root: Hash256,
    pub deposit_count: u64,
}

impl Into<Eth1Data> for Eth1Snapshot {
    fn into(self) -> Eth1Data {
        Eth1Data {
            deposit_root: self.deposit_root,
            deposit_count: self.deposit_count,
            block_hash: self.block.hash,
        }
    }
}

/// Stores block and deposit contract information and provides queries based upon the block
/// timestamp.
#[derive(Debug, PartialEq, Clone)]
pub struct BlockCache {
    items: Vec<Eth1Snapshot>,
    offset: usize,
}

impl BlockCache {
    /// Returns a new, empty cache.
    pub fn new(offset: usize) -> Self {
        Self {
            items: vec![],
            offset: offset,
        }
    }

    /// Shortens the cache, keeping the latest `len` blocks and dropping the rest.
    ///
    /// If `len` is greater than the vector's current length, this has no effect.
    ///
    /// Providing `len == 0` is a no-op.
    pub fn truncate(&mut self, len: usize) {
        if (len != 0) && len < self.items.len() {
            self.items = self.items.split_off(self.items.len() - len);
            self.offset = self
                .items
                .last()
                .expect("cannot shrink to empty")
                .block
                .number as usize;
        }
    }

    /// Returns the range of block numbers stored in the block cache. All blocks in this range can
    /// be accessed.
    pub fn available_block_numbers(&self) -> Option<RangeInclusive<u64>> {
        Some(self.items.first()?.block.number..=self.items.last()?.block.number)
    }

    /// Returns the block number one higher than the highest currently stored.
    ///
    /// Returns `0` if there are no blocks stored.
    pub fn next_block_number(&self) -> u64 {
        (self.offset + self.items.len()) as u64
    }

    /// Fetches an `Eth1Snapshot` by block number.
    fn get(&self, block_number: u64) -> Option<&Eth1Snapshot> {
        let i = usize::try_from(block_number)
            .ok()?
            .checked_sub(self.offset)?;
        self.items.get(i)
    }

    /// Returns the index of the first `Eth1Snapshot` that is lower than the given `target` time
    /// (assumed to be duration since unix epoch), if any.
    ///
    /// If there are blocks with duplicate timestamps, the block with the highest number is
    /// preferred.
    fn index_at_time(&self, target: Duration) -> Option<usize> {
        let search = self.items.as_slice().binary_search_by(|snapshot| {
            Duration::from_secs(snapshot.block.timestamp).cmp(&target)
        });

        let index = match search {
            // If an exact match for this duration was found, search forward trying to find the
            // block with the highest number that has this the same timestamp.
            //
            // This handles the case where blocks have matching timestamps. Whilst this _shouldn't_
            // be possible in mainnet ethereum, it has been seen when testing with ganache.
            Ok(mut i) => loop {
                match self.items.get(i + 1) {
                    Some(next) if Duration::from_secs(next.block.timestamp) == target => i += 1,
                    None | Some(_) => break i,
                }
            },
            Err(i) => i.saturating_sub(1),
        };

        let snapshot = self.items.get(index)?;

        if Duration::from_secs(snapshot.block.timestamp) <= target {
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
        self.items
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
                    known_blocks: self.items.len(),
                })?;
            let first = last.saturating_sub(max_count.saturating_sub(1));

            self.items
                .get(first..=last)
                .ok_or_else(|| Error::Internal("Inconsistent items length".into()))
                .map(|items| items.into_iter().cloned().map(Into::into).collect())
        }
    }

    /// Insert an `Eth1Snapshot` into `self`, allowing future queries.
    ///
    /// ## Errors
    ///
    /// - If `item.block.block_number - 1` is not already in `self`.
    /// - If `item.block.block_number` is in `self`, but is not identical to the supplied
    /// `Eth1Snapshot`.
    /// - If `item.block.timestamp` is prior to the parent.
    pub fn insert(
        &mut self,
        block: Block,
        deposit_root: Hash256,
        deposit_count: u64,
    ) -> Result<(), Error> {
        let item = Eth1Snapshot {
            block,
            deposit_root,
            deposit_count,
        };

        match (
            item.block.number,
            self.next_block_number(),
            self.available_block_numbers().map(|r| *r.start()),
        ) {
            // There are no other items in `self`.
            //
            // Add the item, set the offset.
            (n, _, None) => {
                self.offset = usize::try_from(n).map_err(|_| Error::BlockNumberTooLarge(n))?;
                self.items.push(item);
                Ok(())
            }
            // There are items in `self` and the item is the next item.
            //
            // Add the item, if its timestamp is greater than the entry prior to it.
            (n, next, Some(_)) if n == next => {
                let previous = self
                    .items
                    .last()
                    .ok_or_else(|| Error::Internal("Previous item should exist".into()))?;
                if previous.block.timestamp <= item.block.timestamp {
                    self.items.push(item);
                    Ok(())
                } else {
                    Err(Error::InconsistentTimestamp {
                        parent: previous.block.timestamp,
                        child: item.block.timestamp,
                    })
                }
            }
            // There are items in self and the given item has a known block number.
            //
            // Compare the given item with the stored one.
            (n, next, Some(first)) if (first..next).contains(&n) => {
                let existing = self
                    .get(n)
                    .ok_or_else(|| Error::Internal(format!("Missing block: {:?}", n)))?;

                if *existing == item {
                    Ok(())
                } else {
                    Err(Error::Conflicting(n))
                }
            }
            // There are items in `self` but the item is not the next item.
            //
            // Do not add the item.
            (n, next, _) => Err(Error::NonConsecutive {
                given: n,
                expected: next,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_snapshot(i: u64, interval_secs: u64) -> Eth1Snapshot {
        Eth1Snapshot {
            block: Block {
                hash: Hash256::from_low_u64_be(i),
                timestamp: i * interval_secs,
                number: i,
            },
            deposit_root: Hash256::from_low_u64_be(i << 32),
            deposit_count: i,
        }
    }

    fn get_snapshots(n: usize, interval_secs: u64) -> Vec<Eth1Snapshot> {
        (0..n as u64)
            .into_iter()
            .map(|i| get_snapshot(i, interval_secs))
            .collect()
    }

    fn insert(cache: &mut BlockCache, s: Eth1Snapshot) -> Result<(), Error> {
        cache.insert(s.block, s.deposit_root, s.deposit_count)
    }

    #[test]
    fn truncate() {
        let n = 16;
        let snapshots = get_snapshots(n, 10);

        let mut cache = BlockCache::new(0);

        for snapshot in snapshots {
            insert(&mut cache, snapshot.clone()).expect("should add consecutive snapshots");
        }

        for len in vec![1, 2, 3, 4, 8, 15, 16] {
            let mut cache = cache.clone();

            cache.truncate(len);

            assert_eq!(cache.items.len(), len, "should truncate to length: {}", len);
        }

        let mut cache_2 = cache.clone();
        cache_2.truncate(0);
        assert_eq!(cache_2.items.len(), n, "truncate to 0 should be a no-op");

        let mut cache_2 = cache.clone();
        cache_2.truncate(17);
        assert_eq!(
            cache_2.items.len(),
            n,
            "truncate to larger than n should be a no-op"
        );
    }

    #[test]
    fn inserts() {
        let n = 16;
        let snapshots = get_snapshots(n, 10);

        let mut cache = BlockCache::new(0);

        for snapshot in snapshots {
            insert(&mut cache, snapshot.clone()).expect("should add consecutive snapshots");
        }

        // No error for re-adding a snapshot identical to one that exists.
        assert!(insert(&mut cache, get_snapshot(n as u64 - 1, 10)).is_ok());

        // Error for re-adding a snapshot that is different to the one that exists.
        assert!(insert(&mut cache, get_snapshot(n as u64 - 1, 11)).is_err());

        // Error for adding non-consecutive snapshots.
        assert!(insert(&mut cache, get_snapshot(n as u64 + 1, 10)).is_err());
        assert!(insert(&mut cache, get_snapshot(n as u64 + 2, 10)).is_err());

        // Error for adding timestamp prior to previous.
        assert!(insert(&mut cache, get_snapshot(n as u64, 1)).is_err());
        // Double check to make sure previous test was only affected by timestamp.
        assert!(insert(&mut cache, get_snapshot(n as u64, 10)).is_ok());
    }

    #[test]
    fn duplicate_timestamp() {
        let mut snapshots = get_snapshots(7, 10);

        snapshots[0].block.timestamp = 0;
        snapshots[1].block.timestamp = 10;
        snapshots[2].block.timestamp = 10;
        snapshots[3].block.timestamp = 20;
        snapshots[4].block.timestamp = 30;
        snapshots[5].block.timestamp = 40;
        snapshots[6].block.timestamp = 40;

        let mut cache = BlockCache::new(0);

        for snapshot in &snapshots {
            insert(&mut cache, snapshot.clone()).expect("should add consecutive snapshots");
        }

        // Ensures that the given `target` finds the snapsnot at `snapshots[i]`.
        let do_test = |target, i: usize| {
            assert_eq!(
                cache.get_eth1_data_ancestors(target, 1),
                Ok(vec![snapshots[i].clone().into()]),
                "should find snapshot {} for timestamp {}",
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

    #[test]
    fn snapshot_at_time_valid() {
        let n = 16;
        let duration = 10;
        let snapshots = get_snapshots(n, duration);

        let mut cache = BlockCache::new(0);

        for snapshot in snapshots {
            insert(&mut cache, snapshot.clone()).expect("should add consecutive snapshots");
        }

        for i in 0..n as u64 {
            // Should find exact match when times match.
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs(i * duration)),
                Some(get_snapshot(i, 10).into()),
                "should find eth1 data with exact time for {}",
                i
            );

            // Should find prior when searching between times (low duration).
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs(i * duration + 1)),
                Some(get_snapshot(i, 10).into()),
                "should find prior low eth1 data when searching between durations for  {}",
                i
            );

            // Should find prior when searching between times (high duration).
            assert_eq!(
                cache.eth1_data_at_time(Duration::from_secs((i + 1) * duration - 1)),
                Some(get_snapshot(i, 10).into()),
                "should find prior high eth1 data when searching between durations for  {}",
                i
            );
        }
    }

    #[test]
    fn snapshot_at_time_invalid() {
        let x = 2;
        let duration = 10;

        let mut cache = BlockCache::new(0);

        // Should return none on empty cache.
        assert!(cache.eth1_data_at_time(Duration::from_secs(x)).is_none());

        insert(&mut cache, get_snapshot(x, duration)).expect("should add first snapshot");

        // Should return none for prior time.
        assert!(cache
            .eth1_data_at_time(Duration::from_secs((x - 1) * duration))
            .is_none());
    }

    #[test]
    fn snapshot_ancestors_valid() {
        let n = 16;
        let duration = 10;
        let snapshots = get_snapshots(n, duration);

        let mut cache = BlockCache::new(0);

        for snapshot in &snapshots {
            insert(&mut cache, snapshot.clone()).expect("should add consecutive snapshots");
        }

        for i in 0..n as u64 {
            for max_count in 0..i as usize {
                let ancestors: Vec<Eth1Data> = snapshots[0..=i as usize]
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
    fn snapshot_ancestors_invalid() {
        let x = 2;
        let duration = 10;

        let mut cache = BlockCache::new(0);

        // Should return error on empty cache.
        assert!(cache
            .get_eth1_data_ancestors(Duration::from_secs(x), 1)
            .is_err());

        insert(&mut cache, get_snapshot(x, duration)).expect("should add first snapshot");

        // Should return error for prior time.
        assert!(cache
            .get_eth1_data_ancestors(Duration::from_secs((x - 1) * duration), 1)
            .is_err());
    }
}
