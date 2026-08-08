use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet};
use types::{BuilderIndex, Hash256, Slot};

type SeenEnvelopeMap = BTreeMap<Slot, HashSet<(Hash256, BuilderIndex)>>;

pub struct GossipSeenEnvelopeCache {
    seen_envelopes: RwLock<SeenEnvelopeMap>,
}

impl Default for GossipSeenEnvelopeCache {
    fn default() -> Self {
        Self {
            seen_envelopes: RwLock::new(BTreeMap::new()),
        }
    }
}

impl GossipSeenEnvelopeCache {
    /// Mark the payload envelope as seen for the tuple `(slot, block_root, builder_index)`
    pub fn mark_envelope_seen(&self, slot: Slot, block_root: Hash256, builder_index: BuilderIndex) {
        let mut seen_envelopes = self.seen_envelopes.write();
        seen_envelopes
            .entry(slot)
            .or_default()
            .insert((block_root, builder_index));
    }

    /// Checks if a payload envelope revealed by `builder_index` at `block_root`
    /// was already seen for `slot`
    pub fn has_seen_envelope(
        &self,
        slot: Slot,
        block_root: Hash256,
        builder_index: BuilderIndex,
    ) -> bool {
        self.seen_envelopes
            .read()
            .get(&slot)
            .is_some_and(|seen| seen.contains(&(block_root, builder_index)))
    }

    /// Prune anything before `current_slot`
    pub fn prune(&self, current_slot: Slot) {
        self.seen_envelopes
            .write()
            .retain(|&slot, _| slot >= current_slot);
    }
}

#[cfg(test)]
mod tests {

    use super::GossipSeenEnvelopeCache;
    use types::{BuilderIndex, Hash256, Slot};

    #[test]
    fn marks_envelope_as_seen() {
        let cache = GossipSeenEnvelopeCache::default();
        let slot = Slot::new(1);
        let block_root = Hash256::random();
        let builder_index: BuilderIndex = 1;

        cache.mark_envelope_seen(slot, block_root, builder_index);

        assert!(cache.has_seen_envelope(slot, block_root, builder_index));
    }

    #[test]
    fn prune_removes_entries_older_than_current_slot() {
        let cache = GossipSeenEnvelopeCache::default();
        let block_root = Hash256::random();
        let builder_index: BuilderIndex = 1;

        for slot in 0..=10 {
            cache.mark_envelope_seen(Slot::new(slot), block_root, builder_index);
        }

        cache.prune(Slot::new(8));

        // Slot 1-7 pruned
        for slot in 1..=7 {
            assert!(!cache.has_seen_envelope(Slot::new(slot), block_root, builder_index));
        }

        // Slot 8-10 retained
        for slot in 8..=10 {
            assert!(cache.has_seen_envelope(Slot::new(slot), block_root, builder_index));
        }
    }
}
