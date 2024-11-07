//! This module provides the `BlockTimesCache' which contains information regarding block timings.
//!
//! This provides `BeaconChain` and associated functions with access to the timestamps of when a
//! certain block was observed, imported and set as head.
//! This allows for better traceability and allows us to determine the root cause for why a block
//! was set as head late.
//! This allows us to distingush between the following scenarios:
//! - The block was observed late.
//! - We were too slow to import it.
//! - We were too slow to set it as head.

use eth2::types::{Hash256, Slot};
use std::collections::HashMap;
use std::time::Duration;

type BlockRoot = Hash256;

#[derive(Clone, Default)]
pub struct Timestamps {
    pub observed: Option<Duration>,
    pub all_blobs_observed: Option<Duration>,
    pub consensus_verified: Option<Duration>,
    pub started_execution: Option<Duration>,
    pub executed: Option<Duration>,
    pub attestable: Option<Duration>,
    pub imported: Option<Duration>,
    pub set_as_head: Option<Duration>,
}

// Helps arrange delay data so it is more relevant to metrics.
#[derive(Debug, Default)]
pub struct BlockDelays {
    /// Time after start of slot we saw the block.
    pub observed: Option<Duration>,
    /// The time after the start of the slot we saw all blobs.
    pub all_blobs_observed: Option<Duration>,
    /// The time it took to complete consensus verification of the block.
    pub consensus_verification_time: Option<Duration>,
    /// The time it took to complete execution verification of the block.
    pub execution_time: Option<Duration>,
    /// The delay from the start of the slot before the block became available
    ///
    /// Equal to max(`observed + execution_time`, `all_blobs_observed`).
    pub available: Option<Duration>,
    /// Time after `available`.
    pub attestable: Option<Duration>,
    /// Time
    /// ALSO time after `available`.
    ///
    /// We need to use `available` again rather than `attestable` to handle the case where the block
    /// does not get added to the early-attester cache.
    pub imported: Option<Duration>,
    /// Time after `imported`.
    pub set_as_head: Option<Duration>,
}

impl BlockDelays {
    fn new(times: Timestamps, slot_start_time: Duration) -> BlockDelays {
        let observed = times
            .observed
            .and_then(|observed_time| observed_time.checked_sub(slot_start_time));
        let all_blobs_observed = times
            .all_blobs_observed
            .and_then(|all_blobs_observed| all_blobs_observed.checked_sub(slot_start_time));
        let consensus_verification_time = times
            .consensus_verified
            .and_then(|consensus_verified| consensus_verified.checked_sub(times.observed?));
        let execution_time = times
            .executed
            .and_then(|executed| executed.checked_sub(times.started_execution?));
        // Duration since UNIX epoch at which block became available.
        let available_time = times
            .executed
            .map(|executed| std::cmp::max(executed, times.all_blobs_observed.unwrap_or_default()));
        // Duration from the start of the slot until the block became available.
        let available_delay =
            available_time.and_then(|available_time| available_time.checked_sub(slot_start_time));
        let attestable = times
            .attestable
            .and_then(|attestable_time| attestable_time.checked_sub(slot_start_time));
        let imported = times
            .imported
            .and_then(|imported_time| imported_time.checked_sub(available_time?));
        let set_as_head = times
            .set_as_head
            .and_then(|set_as_head_time| set_as_head_time.checked_sub(times.imported?));
        BlockDelays {
            observed,
            all_blobs_observed,
            consensus_verification_time,
            execution_time,
            available: available_delay,
            attestable,
            imported,
            set_as_head,
        }
    }
}

// If the block was received via gossip, we can record the client type of the peer which sent us
// the block.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BlockPeerInfo {
    pub id: Option<String>,
    pub client: Option<String>,
}

pub struct BlockTimesCacheValue {
    pub slot: Slot,
    pub timestamps: Timestamps,
    pub peer_info: BlockPeerInfo,
}

impl BlockTimesCacheValue {
    fn new(slot: Slot) -> Self {
        BlockTimesCacheValue {
            slot,
            timestamps: Default::default(),
            peer_info: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct BlockTimesCache {
    pub cache: HashMap<BlockRoot, BlockTimesCacheValue>,
}

/// Helper methods to read from and write to the cache.
impl BlockTimesCache {
    /// Set the observation time for `block_root` to `timestamp` if `timestamp` is less than
    /// any previous timestamp at which this block was observed.
    pub fn set_time_observed(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        timestamp: Duration,
        peer_id: Option<String>,
        peer_client: Option<String>,
    ) {
        let block_times = self
            .cache
            .entry(block_root)
            .or_insert_with(|| BlockTimesCacheValue::new(slot));
        match block_times.timestamps.observed {
            Some(existing_observation_time) if existing_observation_time <= timestamp => {
                // Existing timestamp is earlier, do nothing.
            }
            _ => {
                // No existing timestamp, or new timestamp is earlier.
                block_times.timestamps.observed = Some(timestamp);
                block_times.peer_info = BlockPeerInfo {
                    id: peer_id,
                    client: peer_client,
                };
            }
        }
    }

    pub fn set_time_blob_observed(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        timestamp: Duration,
    ) {
        // Unlike other functions in this file, we update the blob observed time only if it is
        // *greater* than existing blob observation times. This allows us to know the observation
        // time of the last blob to arrive.
        let block_times = self
            .cache
            .entry(block_root)
            .or_insert_with(|| BlockTimesCacheValue::new(slot));
        if block_times
            .timestamps
            .all_blobs_observed
            .map_or(true, |prev| timestamp > prev)
        {
            block_times.timestamps.all_blobs_observed = Some(timestamp);
        }
    }

    /// Set the timestamp for `field` if that timestamp is less than any previously known value.
    ///
    /// If no previous value is known for the field, then the supplied timestamp will always be
    /// stored.
    pub fn set_time_if_less(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        field: impl Fn(&mut Timestamps) -> &mut Option<Duration>,
        timestamp: Duration,
    ) {
        let block_times = self
            .cache
            .entry(block_root)
            .or_insert_with(|| BlockTimesCacheValue::new(slot));
        let existing_timestamp = field(&mut block_times.timestamps);
        if existing_timestamp.map_or(true, |prev| timestamp < prev) {
            *existing_timestamp = Some(timestamp);
        }
    }

    pub fn set_time_consensus_verified(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        timestamp: Duration,
    ) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.consensus_verified,
            timestamp,
        )
    }

    pub fn set_time_executed(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.executed,
            timestamp,
        )
    }

    pub fn set_time_started_execution(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        timestamp: Duration,
    ) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.started_execution,
            timestamp,
        )
    }

    pub fn set_time_attestable(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.attestable,
            timestamp,
        )
    }

    pub fn set_time_imported(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.imported,
            timestamp,
        )
    }

    pub fn set_time_set_as_head(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.set_as_head,
            timestamp,
        )
    }

    pub fn get_block_delays(
        &self,
        block_root: BlockRoot,
        slot_start_time: Duration,
    ) -> BlockDelays {
        if let Some(block_times) = self.cache.get(&block_root) {
            BlockDelays::new(block_times.timestamps.clone(), slot_start_time)
        } else {
            BlockDelays::default()
        }
    }

    pub fn get_peer_info(&self, block_root: BlockRoot) -> BlockPeerInfo {
        if let Some(block_info) = self.cache.get(&block_root) {
            block_info.peer_info.clone()
        } else {
            BlockPeerInfo::default()
        }
    }

    // Prune the cache to only store the most recent 2 epochs.
    pub fn prune(&mut self, current_slot: Slot) {
        self.cache
            .retain(|_, cache| cache.slot > current_slot.saturating_sub(64_u64));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use types::FixedBytesExtended;

    #[test]
    fn observed_time_uses_minimum() {
        let mut cache = BlockTimesCache::default();

        let block_root = Hash256::zero();
        let slot = Slot::new(100);

        let slot_start_time = Duration::from_secs(0);

        let ts1 = Duration::from_secs(5);
        let ts2 = Duration::from_secs(6);
        let ts3 = Duration::from_secs(4);

        let peer_info2 = BlockPeerInfo {
            id: Some("peer2".to_string()),
            client: Some("lighthouse".to_string()),
        };

        let peer_info3 = BlockPeerInfo {
            id: Some("peer3".to_string()),
            client: Some("prysm".to_string()),
        };

        cache.set_time_observed(block_root, slot, ts1, None, None);

        assert_eq!(
            cache.get_block_delays(block_root, slot_start_time).observed,
            Some(ts1)
        );
        assert_eq!(cache.get_peer_info(block_root), BlockPeerInfo::default());

        // Second observation with higher timestamp should not override anything, even though it has
        // superior peer info.
        cache.set_time_observed(
            block_root,
            slot,
            ts2,
            peer_info2.id.clone(),
            peer_info2.client.clone(),
        );

        assert_eq!(
            cache.get_block_delays(block_root, slot_start_time).observed,
            Some(ts1)
        );
        assert_eq!(cache.get_peer_info(block_root), BlockPeerInfo::default());

        // Third observation with lower timestamp should override everything.
        cache.set_time_observed(
            block_root,
            slot,
            ts3,
            peer_info3.id.clone(),
            peer_info3.client.clone(),
        );

        assert_eq!(
            cache.get_block_delays(block_root, slot_start_time).observed,
            Some(ts3)
        );
        assert_eq!(cache.get_peer_info(block_root), peer_info3);
    }
}
