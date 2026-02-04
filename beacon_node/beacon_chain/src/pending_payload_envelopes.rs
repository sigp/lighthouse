//! Provides the `PendingPayloadEnvelopes` cache for storing execution payload envelopes
//! that have been produced during local block production but not yet imported to fork choice.
//!
//! For local building, the envelope is created during block production.
//! This cache holds the envelopes temporarily until the proposer can sign and publish the payload.

use std::collections::HashMap;
use types::{EthSpec, ExecutionPayloadEnvelope, Hash256, Slot};

/// Cache for pending execution payload envelopes awaiting publishing.
///
/// Envelopes are keyed by beacon block root and pruned based on slot age.
pub struct PendingPayloadEnvelopes<E: EthSpec> {
    /// Maximum number of slots to keep envelopes before pruning.
    max_slot_age: u64,
    /// The envelopes, keyed by beacon block root.
    envelopes: HashMap<Hash256, ExecutionPayloadEnvelope<E>>,
}

impl<E: EthSpec> Default for PendingPayloadEnvelopes<E> {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_SLOT_AGE)
    }
}

impl<E: EthSpec> PendingPayloadEnvelopes<E> {
    /// Default maximum slot age before pruning (2 slots).
    pub const DEFAULT_MAX_SLOT_AGE: u64 = 2;

    /// Create a new cache with the specified maximum slot age.
    pub fn new(max_slot_age: u64) -> Self {
        Self {
            max_slot_age,
            envelopes: HashMap::new(),
        }
    }

    /// Insert a pending envelope into the cache.
    pub fn insert(&mut self, block_root: Hash256, envelope: ExecutionPayloadEnvelope<E>) {
        self.envelopes.insert(block_root, envelope);
    }

    /// Get a pending envelope by block root.
    pub fn get(&self, block_root: &Hash256) -> Option<&ExecutionPayloadEnvelope<E>> {
        self.envelopes.get(block_root)
    }

    /// Remove and return a pending envelope by block root.
    pub fn remove(&mut self, block_root: &Hash256) -> Option<ExecutionPayloadEnvelope<E>> {
        self.envelopes.remove(block_root)
    }

    /// Check if an envelope exists for the given block root.
    pub fn contains(&self, block_root: &Hash256) -> bool {
        self.envelopes.contains_key(block_root)
    }

    /// Prune envelopes older than `current_slot - max_slot_age`.
    ///
    /// This removes stale envelopes from blocks that were never imported.
    pub fn prune(&mut self, current_slot: Slot) {
        let min_slot = current_slot.saturating_sub(self.max_slot_age);
        self.envelopes
            .retain(|_, envelope| envelope.slot >= min_slot);
    }

    /// Returns the number of pending envelopes in the cache.
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{ExecutionPayloadGloas, ExecutionRequests, MainnetEthSpec};

    type E = MainnetEthSpec;

    fn make_envelope(slot: Slot, block_root: Hash256) -> ExecutionPayloadEnvelope<E> {
        ExecutionPayloadEnvelope {
            payload: ExecutionPayloadGloas::default(),
            execution_requests: ExecutionRequests::default(),
            builder_index: 0,
            beacon_block_root: block_root,
            slot,
            state_root: Hash256::ZERO,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let block_root = Hash256::repeat_byte(1);
        let envelope = make_envelope(Slot::new(1), block_root);

        assert!(!cache.contains(&block_root));
        assert_eq!(cache.len(), 0);

        cache.insert(block_root, envelope.clone());

        assert!(cache.contains(&block_root));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&block_root), Some(&envelope));
    }

    #[test]
    fn remove() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let block_root = Hash256::repeat_byte(1);
        let envelope = make_envelope(Slot::new(1), block_root);

        cache.insert(block_root, envelope.clone());
        assert!(cache.contains(&block_root));

        let removed = cache.remove(&block_root);
        assert_eq!(removed, Some(envelope));
        assert!(!cache.contains(&block_root));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn prune_old_envelopes() {
        let mut cache = PendingPayloadEnvelopes::<E>::new(2);

        // Insert envelope at slot 5
        let block_root_1 = Hash256::repeat_byte(1);
        let envelope_1 = make_envelope(Slot::new(5), block_root_1);
        cache.insert(block_root_1, envelope_1);

        // Insert envelope at slot 10
        let block_root_2 = Hash256::repeat_byte(2);
        let envelope_2 = make_envelope(Slot::new(10), block_root_2);
        cache.insert(block_root_2, envelope_2);

        assert_eq!(cache.len(), 2);

        // Prune at slot 10 with max_slot_age=2, should keep slots >= 8
        cache.prune(Slot::new(10));

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains(&block_root_1)); // slot 5 < 8, pruned
        assert!(cache.contains(&block_root_2)); // slot 10 >= 8, kept
    }
}
