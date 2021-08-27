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

#[derive(Clone)]
pub struct Timestamps {
    pub observed: Option<Duration>,
    pub imported: Option<Duration>,
    pub set_as_head: Option<Duration>,
}

impl Default for Timestamps {
    fn default() -> Self {
        Timestamps {
            observed: None,
            imported: None,
            set_as_head: None,
        }
    }
}

// Helps arrange delay data so it is more relevant to metrics.
pub struct BlockDelays {
    pub observed: Option<Duration>,
    pub imported: Option<Duration>,
    pub set_as_head: Option<Duration>,
}

impl Default for BlockDelays {
    fn default() -> Self {
        BlockDelays {
            observed: None,
            imported: None,
            set_as_head: None,
        }
    }
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

pub struct BlockTimesCacheValue {
    pub timestamps: Timestamps,
    pub slot: Slot,
}

#[derive(Default)]
pub struct BlockTimesCache {
    pub cache: HashMap<BlockRoot, BlockTimesCacheValue>,
}

/// Helper methods to read from and write to the cache.
impl BlockTimesCache {
    pub fn set_time_observed(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        if let Some(mut block_times) = self.cache.get_mut(&block_root) {
            block_times.timestamps.observed = Some(timestamp);
        } else {
            let timestamps = Timestamps {
                observed: Some(timestamp),
                ..Default::default()
            };
            self.cache
                .insert(block_root, BlockTimesCacheValue { timestamps, slot });
        }
    }

    pub fn set_time_imported(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        if let Some(mut block_times) = self.cache.get_mut(&block_root) {
            block_times.timestamps.imported = Some(timestamp);
        } else {
            let timestamps = Timestamps {
                imported: Some(timestamp),
                ..Default::default()
            };
            self.cache
                .insert(block_root, BlockTimesCacheValue { timestamps, slot });
        }
    }

    pub fn set_time_set_as_head(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        if let Some(mut block_times) = self.cache.get_mut(&block_root) {
            block_times.timestamps.set_as_head = Some(timestamp);
        } else {
            let timestamps = Timestamps {
                set_as_head: Some(timestamp),
                ..Default::default()
            };
            self.cache
                .insert(block_root, BlockTimesCacheValue { timestamps, slot });
        }
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

    // Prune the cache to only store the most recent 2 epochs.
    pub fn prune(&mut self, current_slot: Slot) {
        self.cache.retain(|_, cache| cache.slot < current_slot - 64)
    }
}
