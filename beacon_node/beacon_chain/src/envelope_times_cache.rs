//! This module provides the `EnvelopeTimesCache` which contains information regarding payload
//! envelope timings.
//!
//! This provides `BeaconChain` and associated functions with access to the timestamps of when a
//! payload envelope was observed, verified, executed, and imported.
//! This allows for better traceability and allows us to determine the root cause for why an
//! envelope was imported late.
//! This allows us to distinguish between the following scenarios:
//! - The envelope was observed late.
//! - Consensus verification was slow.
//! - Execution verification was slow.
//! - The DB write was slow.

use eth2::types::{Hash256, Slot};
use std::collections::HashMap;
use std::time::Duration;

type BlockRoot = Hash256;

#[derive(Clone, Default)]
pub struct EnvelopeTimestamps {
    /// When the envelope was first observed (gossip or RPC).
    pub observed: Option<Duration>,
    /// When consensus verification (state transition) completed.
    pub consensus_verified: Option<Duration>,
    /// When execution layer verification started.
    pub started_execution: Option<Duration>,
    /// When execution layer verification completed.
    pub executed: Option<Duration>,
    /// When the envelope was imported into the DB.
    pub imported: Option<Duration>,
}

/// Delay data for envelope processing, computed relative to the slot start time.
#[derive(Debug, Default)]
pub struct EnvelopeDelays {
    /// Time after start of slot we saw the envelope.
    pub observed: Option<Duration>,
    /// The time it took to complete consensus verification of the envelope.
    pub consensus_verification_time: Option<Duration>,
    /// The time it took to complete execution verification of the envelope.
    pub execution_time: Option<Duration>,
    /// Time after execution until the envelope was imported.
    pub imported: Option<Duration>,
}

impl EnvelopeDelays {
    fn new(times: EnvelopeTimestamps, slot_start_time: Duration) -> EnvelopeDelays {
        let observed = times
            .observed
            .and_then(|observed_time| observed_time.checked_sub(slot_start_time));
        let consensus_verification_time = times
            .consensus_verified
            .and_then(|consensus_verified| consensus_verified.checked_sub(times.observed?));
        let execution_time = times
            .executed
            .and_then(|executed| executed.checked_sub(times.started_execution?));
        let imported = times
            .imported
            .and_then(|imported_time| imported_time.checked_sub(times.executed?));
        EnvelopeDelays {
            observed,
            consensus_verification_time,
            execution_time,
            imported,
        }
    }
}

pub struct EnvelopeTimesCacheValue {
    pub slot: Slot,
    pub timestamps: EnvelopeTimestamps,
    pub peer_id: Option<String>,
}

impl EnvelopeTimesCacheValue {
    fn new(slot: Slot) -> Self {
        EnvelopeTimesCacheValue {
            slot,
            timestamps: Default::default(),
            peer_id: None,
        }
    }
}

#[derive(Default)]
pub struct EnvelopeTimesCache {
    pub cache: HashMap<BlockRoot, EnvelopeTimesCacheValue>,
}

impl EnvelopeTimesCache {
    /// Set the observation time for `block_root` to `timestamp` if `timestamp` is less than
    /// any previous timestamp at which this envelope was observed.
    pub fn set_time_observed(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        timestamp: Duration,
        peer_id: Option<String>,
    ) {
        let entry = self
            .cache
            .entry(block_root)
            .or_insert_with(|| EnvelopeTimesCacheValue::new(slot));
        match entry.timestamps.observed {
            Some(existing) if existing <= timestamp => {
                // Existing timestamp is earlier, do nothing.
            }
            _ => {
                entry.timestamps.observed = Some(timestamp);
                entry.peer_id = peer_id;
            }
        }
    }

    /// Set the timestamp for `field` if that timestamp is less than any previously known value.
    fn set_time_if_less(
        &mut self,
        block_root: BlockRoot,
        slot: Slot,
        field: impl Fn(&mut EnvelopeTimestamps) -> &mut Option<Duration>,
        timestamp: Duration,
    ) {
        let entry = self
            .cache
            .entry(block_root)
            .or_insert_with(|| EnvelopeTimesCacheValue::new(slot));
        let existing_timestamp = field(&mut entry.timestamps);
        if existing_timestamp.is_none_or(|prev| timestamp < prev) {
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

    pub fn set_time_executed(&mut self, block_root: BlockRoot, slot: Slot, timestamp: Duration) {
        self.set_time_if_less(
            block_root,
            slot,
            |timestamps| &mut timestamps.executed,
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

    pub fn get_envelope_delays(
        &self,
        block_root: BlockRoot,
        slot_start_time: Duration,
    ) -> EnvelopeDelays {
        if let Some(entry) = self.cache.get(&block_root) {
            EnvelopeDelays::new(entry.timestamps.clone(), slot_start_time)
        } else {
            EnvelopeDelays::default()
        }
    }

    /// Prune the cache to only store the most recent 2 epochs.
    pub fn prune(&mut self, current_slot: Slot) {
        self.cache
            .retain(|_, entry| entry.slot > current_slot.saturating_sub(64_u64));
    }
}
