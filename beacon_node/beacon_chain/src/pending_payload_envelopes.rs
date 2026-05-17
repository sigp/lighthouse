//! Provides the `PendingPayloadEnvelopes` cache for storing execution payload envelopes
//! that have been produced during local block production.
//!
//! For local building, the envelope is created during block production.
//! This cache holds the envelopes temporarily until the validator fetches, signs,
//! and publishes the payload.

use std::collections::HashMap;
use types::{BlobsList, EthSpec, ExecutionPayloadEnvelope, Slot};

pub struct PendingEnvelopeData<E: EthSpec> {
    pub envelope: ExecutionPayloadEnvelope<E>,
    pub blobs: Option<BlobsList<E>>,
}

/// Cache for pending execution payload envelopes awaiting publishing.
///
/// Envelopes are keyed by slot and pruned based on slot age.
/// This cache is only used for local building.
pub struct PendingPayloadEnvelopes<E: EthSpec> {
    /// Maximum number of slots to keep envelopes before pruning.
    max_slot_age: u64,
    /// The envelopes, keyed by slot.
    envelopes: HashMap<Slot, PendingEnvelopeData<E>>,
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
    pub fn insert(&mut self, slot: Slot, data: PendingEnvelopeData<E>) {
        self.envelopes.insert(slot, data);
    }

    /// Get a pending envelope by slot.
    pub fn get(&self, slot: Slot) -> Option<&ExecutionPayloadEnvelope<E>> {
        self.envelopes.get(&slot).map(|d| &d.envelope)
    }

    /// Remove and return the blobs and proofs for a slot, leaving the envelope in place.
    pub fn take_blobs(&mut self, slot: Slot) -> Option<BlobsList<E>> {
        self.envelopes.get_mut(&slot).and_then(|d| d.blobs.take())
    }

    /// Remove and return a pending envelope by slot.
    pub fn remove(&mut self, slot: Slot) -> Option<ExecutionPayloadEnvelope<E>> {
        self.envelopes.remove(&slot).map(|d| d.envelope)
    }

    /// Check if an envelope exists for the given slot.
    pub fn contains(&self, slot: Slot) -> bool {
        self.envelopes.contains_key(&slot)
    }

    /// Prune envelopes older than `current_slot - max_slot_age`.
    pub fn prune(&mut self, current_slot: Slot) {
        let min_slot = current_slot.saturating_sub(self.max_slot_age);
        self.envelopes.retain(|slot, _| *slot >= min_slot);
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
    use types::{
        ExecutionPayloadEnvelopeGloas, ExecutionPayloadGloas, ExecutionRequests, Hash256,
        MainnetEthSpec,
    };

    type E = MainnetEthSpec;

    fn make_envelope(slot: Slot) -> PendingEnvelopeData<E> {
        PendingEnvelopeData {
            envelope: ExecutionPayloadEnvelope::Gloas(ExecutionPayloadEnvelopeGloas {
                payload: ExecutionPayloadGloas {
                    slot_number: slot,
                    ..ExecutionPayloadGloas::default()
                },
                execution_requests: ExecutionRequests::default(),
                builder_index: 0,
                beacon_block_root: Hash256::ZERO,
                parent_beacon_block_root: Hash256::ZERO,
            }),
            blobs: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let data = make_envelope(slot);

        assert!(!cache.contains(slot));
        assert_eq!(cache.len(), 0);

        cache.insert(slot, data);

        assert!(cache.contains(slot));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(slot).is_some());
    }

    #[test]
    fn remove() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let data = make_envelope(slot);

        cache.insert(slot, data);
        assert!(cache.contains(slot));

        let removed = cache.remove(slot);
        assert!(removed.is_some());
        assert!(!cache.contains(slot));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn take_blobs_returns_once() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);

        let blobs = BlobsList::<E>::default();
        let data = PendingEnvelopeData {
            envelope: make_envelope(slot).envelope,
            blobs: Some(blobs),
        };
        cache.insert(slot, data);

        let taken = cache.take_blobs(slot);
        assert!(taken.is_some());

        let taken_again = cache.take_blobs(slot);
        assert!(taken_again.is_none());

        assert!(cache.contains(slot));
        assert!(cache.get(slot).is_some());
    }

    #[test]
    fn take_blobs_returns_none_when_absent() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);

        cache.insert(slot, make_envelope(slot));
        assert!(cache.take_blobs(slot).is_none());

        assert!(cache.take_blobs(Slot::new(99)).is_none());
    }

    #[test]
    fn prune_old_envelopes() {
        let mut cache = PendingPayloadEnvelopes::<E>::new(2);

        let slot_1 = Slot::new(5);
        cache.insert(slot_1, make_envelope(slot_1));

        let slot_2 = Slot::new(10);
        cache.insert(slot_2, make_envelope(slot_2));

        assert_eq!(cache.len(), 2);

        cache.prune(Slot::new(10));

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains(slot_1));
        assert!(cache.contains(slot_2));
    }
}
