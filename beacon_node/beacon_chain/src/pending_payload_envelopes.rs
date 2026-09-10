//! Provides the `PendingPayloadEnvelopes` cache for storing execution payload envelopes for
//! payloads built by this beacon node.
//!
//! The cache is populated during self-build block production or by builder bid
//! production. It holds the envelopes temporarily until the payload builder fetches,
//!  signs, and publishes the envelope.
use std::collections::HashMap;
use std::sync::Arc;
use types::{BlobsList, EthSpec, ExecutionPayloadEnvelope, Hash256, Slot};

pub struct PendingEnvelopeData<E: EthSpec> {
    pub envelope: Arc<ExecutionPayloadEnvelope<E>>,
    pub blobs: Option<Arc<BlobsList<E>>>,
}

/// Cache for pending execution payload envelopes awaiting publishing.
///
/// Envelopes are keyed by the beacon block root they commit to and pruned based on slot age.
/// This cache is only used for local building.
pub struct PendingPayloadEnvelopes<E: EthSpec> {
    /// Maximum number of slots to keep envelopes before pruning.
    max_slot_age: u64,
    /// The envelopes, keyed by beacon block root.
    envelopes: HashMap<Hash256, PendingEnvelopeData<E>>,
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

    /// Insert a pending envelope into the cache, keyed by the beacon block root it commits to.
    pub fn insert(&mut self, data: PendingEnvelopeData<E>) {
        self.envelopes.insert(data.envelope.beacon_block_root, data);
    }

    /// Get a pending envelope by the beacon block root it commits to.
    pub fn get_by_block_root(
        &self,
        beacon_block_root: Hash256,
    ) -> Option<&Arc<ExecutionPayloadEnvelope<E>>> {
        self.envelopes
            .get(&beacon_block_root)
            .map(|data| &data.envelope)
    }

    /// Remove and return the blobs for a beacon block root, leaving the envelope in place.
    pub fn take_blobs(&mut self, beacon_block_root: Hash256) -> Option<Arc<BlobsList<E>>> {
        self.envelopes
            .get_mut(&beacon_block_root)
            .and_then(|data| data.blobs.take())
    }

    /// Remove and return a pending envelope by the beacon block root it commits to.
    pub fn remove(
        &mut self,
        beacon_block_root: Hash256,
    ) -> Option<Arc<ExecutionPayloadEnvelope<E>>> {
        self.envelopes
            .remove(&beacon_block_root)
            .map(|data| data.envelope)
    }

    /// Prune envelopes older than `current_slot - max_slot_age`.
    ///
    /// This removes stale envelopes from blocks that were never published.
    pub fn prune(&mut self, current_slot: Slot) {
        let min_slot = current_slot.saturating_sub(self.max_slot_age);
        self.envelopes
            .retain(|_, data| data.envelope.slot() >= min_slot);
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
    use types::{ExecutionPayloadGloas, ExecutionRequestsGloas, Hash256, MainnetEthSpec};

    type E = MainnetEthSpec;

    fn make_envelope(slot: Slot, beacon_block_root: Hash256) -> PendingEnvelopeData<E> {
        PendingEnvelopeData {
            envelope: Arc::new(ExecutionPayloadEnvelope {
                payload: ExecutionPayloadGloas {
                    slot_number: slot,
                    ..ExecutionPayloadGloas::default()
                },
                execution_requests: ExecutionRequestsGloas::default(),
                builder_index: 0,
                beacon_block_root,
                parent_beacon_block_root: Hash256::ZERO,
            }),
            blobs: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let block_root = Hash256::repeat_byte(42);
        let data = make_envelope(slot, block_root);
        let expected_envelope = data.envelope.clone();

        assert_eq!(cache.len(), 0);

        cache.insert(data);

        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get_by_block_root(block_root),
            Some(&expected_envelope)
        );
        assert_eq!(cache.get_by_block_root(Hash256::repeat_byte(43)), None);
    }

    #[test]
    fn same_slot_different_roots_coexist() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let root_a = Hash256::repeat_byte(1);
        let root_b = Hash256::repeat_byte(2);

        cache.insert(make_envelope(slot, root_a));
        cache.insert(make_envelope(slot, root_b));

        assert_eq!(cache.len(), 2);
        assert!(cache.get_by_block_root(root_a).is_some());
        assert!(cache.get_by_block_root(root_b).is_some());
    }

    #[test]
    fn remove() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let block_root = Hash256::repeat_byte(42);
        let data = make_envelope(slot, block_root);
        let expected_envelope = data.envelope.clone();

        cache.insert(data);
        assert!(cache.get_by_block_root(block_root).is_some());

        let removed = cache.remove(block_root);
        assert_eq!(removed, Some(expected_envelope));
        assert!(cache.get_by_block_root(block_root).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn take_blobs_returns_once() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let block_root = Hash256::repeat_byte(42);

        let blobs = Arc::new(BlobsList::<E>::default());
        let data = PendingEnvelopeData {
            envelope: make_envelope(slot, block_root).envelope,
            blobs: Some(blobs),
        };
        cache.insert(data);

        // First take returns the blobs
        let taken = cache.take_blobs(block_root);
        assert!(taken.is_some());

        // Second take returns None — blobs are consumed
        let taken_again = cache.take_blobs(block_root);
        assert!(taken_again.is_none());

        // Envelope is still in the cache
        assert!(cache.get_by_block_root(block_root).is_some());
    }

    #[test]
    fn take_blobs_returns_none_when_absent() {
        let mut cache = PendingPayloadEnvelopes::<E>::default();
        let slot = Slot::new(1);
        let block_root = Hash256::repeat_byte(42);

        // Insert with no blobs
        cache.insert(make_envelope(slot, block_root));
        assert!(cache.take_blobs(block_root).is_none());

        // Non-existent block root
        assert!(cache.take_blobs(Hash256::repeat_byte(99)).is_none());
    }

    #[test]
    fn prune_old_envelopes() {
        let mut cache = PendingPayloadEnvelopes::<E>::new(2);

        // Insert envelope at slot 5
        let slot_1 = Slot::new(5);
        cache.insert(make_envelope(slot_1, Hash256::repeat_byte(1)));

        // Insert envelope at slot 10
        let slot_2 = Slot::new(10);
        cache.insert(make_envelope(slot_2, Hash256::repeat_byte(2)));

        assert_eq!(cache.len(), 2);

        // Prune at slot 10 with max_slot_age=2, should keep slots >= 8
        cache.prune(Slot::new(10));

        assert_eq!(cache.len(), 1);
        assert!(cache.get_by_block_root(Hash256::repeat_byte(1)).is_none()); // slot 5 < 8, pruned
        assert!(cache.get_by_block_root(Hash256::repeat_byte(2)).is_some()); // slot 10 >= 8, kept
    }
}
