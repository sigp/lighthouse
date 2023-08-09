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
    pub imported: Option<Duration>,
    pub set_as_head: Option<Duration>,
}

// Helps arrange delay data so it is more relevant to metrics.
#[derive(Default)]
pub struct BlockDelays {
    pub observed: Option<Duration>,
    pub imported: Option<Duration>,
    pub set_as_head: Option<Duration>,
}

impl BlockDelays {
    fn new(times: Timestamps, slot_start_time: Duration) -> BlockDelays {
        let observed = times
            .observed
            .and_then(|observed_time| observed_time.checked_sub(slot_start_time));
        let imported = times
            .imported
            .and_then(|imported_time| imported_time.checked_sub(times.observed?));
        let set_as_head = times
            .set_as_head
            .and_then(|set_as_head_time| set_as_head_time.checked_sub(times.imported?));
        BlockDelays {
            observed,
            imported,
            set_as_head,
        }
    }
}

// If the block was received via gossip, we can record the client type of the peer which sent us
// the block.
#[derive(Clone, Default)]
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
        block_times.timestamps.observed = Some(timestamp);
        block_times.peer_info = BlockPeerInfo {
            id: peer_id,
            client: peer_client,
        };
    }

    pub fn set_time_imported(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        let block_times = self
            .cache
            .entry(block_root)
            .or_insert_with(|| BlockTimesCacheValue::new(slot));
        block_times.timestamps.imported = Some(timestamp);
    }

    pub fn set_time_set_as_head(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        let block_times = self
            .cache
            .entry(block_root)
            .or_insert_with(|| BlockTimesCacheValue::new(slot));
        block_times.timestamps.set_as_head = Some(timestamp);
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
