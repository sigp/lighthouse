//! Pending block-carried index-1 attestations awaiting a payload envelope.
//!
//! When block import hits `PayloadNotReceived` for an index-1 vote, the attestation is parked
//! here and applied once the envelope is imported.

use std::collections::HashMap;
use types::{EthSpec, Hash256, IndexedAttestation, Slot};

/// Default maximum attestation slot age before pruning.
pub const DEFAULT_MAX_SLOT_AGE: u64 = 64;

/// Soft cap on total parked attestations across all roots.
pub const DEFAULT_MAX_PENDING_ATTESTATIONS: usize = 4096;

/// Soft cap on parked attestations for a single beacon block root.
pub const DEFAULT_MAX_PER_ROOT: usize = 512;

/// Cache of block-carried index-1 attestations waiting for `payload_received`.
///
/// Keyed by `attestation.data.beacon_block_root`.
pub struct PendingBlockPayloadAttestations<E: EthSpec> {
    max_slot_age: u64,
    max_pending_attestations: usize,
    max_per_root: usize,
    pending: HashMap<Hash256, Vec<IndexedAttestation<E>>>,
    total: usize,
}

impl<E: EthSpec> Default for PendingBlockPayloadAttestations<E> {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_SLOT_AGE,
            DEFAULT_MAX_PENDING_ATTESTATIONS,
            DEFAULT_MAX_PER_ROOT,
        )
    }
}

impl<E: EthSpec> PendingBlockPayloadAttestations<E> {
    pub fn new(max_slot_age: u64, max_pending_attestations: usize, max_per_root: usize) -> Self {
        Self {
            max_slot_age,
            max_pending_attestations,
            max_per_root,
            pending: HashMap::new(),
            total: 0,
        }
    }

    /// Insert a parked attestation. Returns `false` if caps are exceeded (attestation dropped).
    pub fn park(&mut self, root: Hash256, indexed: IndexedAttestation<E>) -> bool {
        if self.total >= self.max_pending_attestations {
            return false;
        }

        let entry = self.pending.entry(root).or_default();
        if entry.len() >= self.max_per_root {
            return false;
        }

        entry.push(indexed);
        self.total = self.total.saturating_add(1);
        true
    }

    /// Remove and return all attestations parked for `root`.
    pub fn drain(&mut self, root: Hash256) -> Vec<IndexedAttestation<E>> {
        let drained = self.pending.remove(&root).unwrap_or_default();
        self.total = self.total.saturating_sub(drained.len());
        drained
    }

    /// Drop attestations whose `data.slot` is older than `current_slot - max_slot_age`.
    pub fn prune(&mut self, current_slot: Slot) {
        let min_slot = current_slot.saturating_sub(self.max_slot_age);
        self.pending.retain(|_, attestations| {
            attestations.retain(|att| att.data().slot >= min_slot);
            !attestations.is_empty()
        });
        self.total = self.pending.values().map(Vec::len).sum();
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn contains_root(&self, root: &Hash256) -> bool {
        self.pending.contains_key(root)
    }

    pub fn count_for_root(&self, root: &Hash256) -> usize {
        self.pending.get(root).map(Vec::len).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{AttestationData, Checkpoint, MainnetEthSpec};

    type E = MainnetEthSpec;

    fn dummy_attestation(slot: u64, root: Hash256) -> IndexedAttestation<E> {
        IndexedAttestation::Base(types::IndexedAttestationBase {
            attesting_indices: Default::default(),
            data: AttestationData {
                slot: Slot::new(slot),
                index: 1,
                beacon_block_root: root,
                source: Checkpoint::default(),
                target: Checkpoint::default(),
            },
            signature: bls::AggregateSignature::empty(),
        })
    }

    #[test]
    fn park_and_drain() {
        let mut cache = PendingBlockPayloadAttestations::<E>::default();
        let root = Hash256::repeat_byte(1);
        assert!(cache.park(root, dummy_attestation(10, root)));
        assert!(cache.park(root, dummy_attestation(11, root)));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.count_for_root(&root), 2);

        let drained = cache.drain(root);
        assert_eq!(drained.len(), 2);
        assert!(cache.is_empty());
        assert!(cache.drain(root).is_empty());
    }

    #[test]
    fn prune_old_slots() {
        let mut cache = PendingBlockPayloadAttestations::<E>::new(2, 100, 100);
        let root = Hash256::repeat_byte(2);
        assert!(cache.park(root, dummy_attestation(1, root)));
        assert!(cache.park(root, dummy_attestation(5, root)));
        cache.prune(Slot::new(5));
        assert_eq!(cache.count_for_root(&root), 1);
        assert_eq!(cache.drain(root)[0].data().slot, Slot::new(5));
    }

    #[test]
    fn respects_caps() {
        let mut cache = PendingBlockPayloadAttestations::<E>::new(64, 2, 1);
        let root_a = Hash256::repeat_byte(3);
        let root_b = Hash256::repeat_byte(4);
        assert!(cache.park(root_a, dummy_attestation(1, root_a)));
        // Per-root cap.
        assert!(!cache.park(root_a, dummy_attestation(2, root_a)));
        assert!(cache.park(root_b, dummy_attestation(1, root_b)));
        // Total cap.
        let root_c = Hash256::repeat_byte(5);
        assert!(!cache.park(root_c, dummy_attestation(1, root_c)));
        assert_eq!(cache.len(), 2);
    }
}
