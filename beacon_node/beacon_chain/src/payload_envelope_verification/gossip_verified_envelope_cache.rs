use std::collections::{BTreeMap, HashSet};

use parking_lot::RwLock;
use types::{BuilderIndex, Hash256, Slot};

/// Tracks which execution payload envelopes have already been seen over gossip, keyed by
/// `(block_root, builder_index)`, so that a second valid `SignedExecutionPayloadEnvelope` for the
/// same block root from the same builder can be ignored per the Gloas `execution_payload` gossip
/// rules.
///
/// This is the envelope counterpart of the seen-builder half of
/// [`GossipVerifiedPayloadBidCache`](crate::payload_bid_verification::payload_bid_cache::GossipVerifiedPayloadBidCache).
/// Unlike the bid cache it does not need to be generic over `BeaconChainTypes`, because it only
/// stores the `(block_root, builder_index)` identity rather than a verified message. The `Slot` is
/// retained purely so entries can be pruned once they fall below the current slot; the dedup
/// identity is `(block_root, builder_index)`.
#[derive(Default)]
pub struct GossipVerifiedEnvelopeCache {
    seen_envelope: RwLock<BTreeMap<Slot, HashSet<(Hash256, BuilderIndex)>>>,
}

impl GossipVerifiedEnvelopeCache {
    /// A gossip verified envelope for `(block_root, builder_index)` already exists at `slot`.
    pub fn seen_envelope(
        &self,
        slot: &Slot,
        block_root: Hash256,
        builder_index: BuilderIndex,
    ) -> bool {
        self.seen_envelope
            .read()
            .get(slot)
            .is_some_and(|seen_envelopes| seen_envelopes.contains(&(block_root, builder_index)))
    }

    /// Record that a valid envelope for `(block_root, builder_index)` at `slot` has been seen.
    pub fn insert_seen_envelope(
        &self,
        slot: Slot,
        block_root: Hash256,
        builder_index: BuilderIndex,
    ) {
        self.seen_envelope
            .write()
            .entry(slot)
            .or_default()
            .insert((block_root, builder_index));
    }

    /// Prune anything before `current_slot`.
    pub fn prune(&self, current_slot: Slot) {
        self.seen_envelope
            .write()
            .retain(|&slot, _| slot >= current_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::GossipVerifiedEnvelopeCache;
    use types::{Hash256, Slot};

    fn root(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    #[test]
    fn seen_envelope_discriminates_by_block_root_and_builder() {
        let cache = GossipVerifiedEnvelopeCache::default();
        let slot = Slot::new(3);

        assert!(!cache.seen_envelope(&slot, root(1), 7));

        cache.insert_seen_envelope(slot, root(1), 7);

        // Same (block_root, builder_index) at the same slot is now seen.
        assert!(cache.seen_envelope(&slot, root(1), 7));
        // A different builder for the same block root is not seen.
        assert!(!cache.seen_envelope(&slot, root(1), 8));
        // A different block root for the same builder is not seen.
        assert!(!cache.seen_envelope(&slot, root(2), 7));
        // The same identity at a different slot is tracked independently.
        assert!(!cache.seen_envelope(&Slot::new(4), root(1), 7));
    }

    #[test]
    fn prune_removes_old_retains_current() {
        let cache = GossipVerifiedEnvelopeCache::default();

        for slot in [1, 2, 3, 7, 8, 9, 10] {
            cache.insert_seen_envelope(Slot::new(slot), root(slot as u8), slot);
        }

        cache.prune(Slot::new(8));

        // Slots 1-7 pruned.
        for slot in [1, 2, 3, 7] {
            assert!(!cache.seen_envelope(&Slot::new(slot), root(slot as u8), slot));
        }
        // Slots 8-10 retained.
        for slot in [8, 9, 10] {
            assert!(cache.seen_envelope(&Slot::new(slot), root(slot as u8), slot));
        }
    }
}
