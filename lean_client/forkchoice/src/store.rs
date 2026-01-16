//! Fork choice store and attestation tracking structures.
//!
//! This module provides the core data structures for fork choice operations.

use lean_consensus::attestation::{Checkpoint, SignedAttestation, Slot};

/// Fork choice store that tracks timing and checkpoint state.
#[derive(Debug, Clone)]
pub struct ForkChoiceStore {
    /// Current time in intervals since genesis.
    pub time_intervals: u64,
    /// Current time in slots (derived from intervals).
    pub time_slots: u64,
    /// Latest justified checkpoint.
    pub latest_justified: Checkpoint,
    /// Latest finalized checkpoint.
    pub latest_finalized: Checkpoint,
}

impl ForkChoiceStore {
    /// Number of intervals per slot.
    pub const INTERVALS_PER_SLOT: u64 = 4;

    /// Creates a new ForkChoiceStore with the given anchor checkpoint.
    pub fn new(anchor_checkpoint: Checkpoint) -> Self {
        Self {
            time_intervals: 0,
            time_slots: 0,
            latest_justified: anchor_checkpoint.clone(),
            latest_finalized: anchor_checkpoint,
        }
    }

    /// Creates a ForkChoiceStore initialized at a specific slot.
    pub fn at_slot(slot: u64, anchor_checkpoint: Checkpoint) -> Self {
        Self {
            time_intervals: slot * Self::INTERVALS_PER_SLOT,
            time_slots: slot,
            latest_justified: anchor_checkpoint.clone(),
            latest_finalized: anchor_checkpoint,
        }
    }

    /// Updates the justified and finalized checkpoints if they are newer.
    pub fn update(&mut self, justified: Checkpoint, finalized: Checkpoint) {
        if justified.slot > self.latest_justified.slot {
            self.latest_justified = justified;
        }
        if finalized.slot > self.latest_finalized.slot {
            self.latest_finalized = finalized;
        }
    }

    /// Returns the current interval within the slot (0-3).
    pub fn current_interval(&self) -> u64 {
        self.time_intervals % Self::INTERVALS_PER_SLOT
    }

    /// Advances time by one interval.
    ///
    /// Returns the new interval number within the slot (0-3).
    pub fn tick(&mut self) -> u64 {
        self.time_intervals += 1;
        let interval = self.current_interval();

        if interval == 0 {
            self.time_slots += 1;
        }

        interval
    }

    /// Advances to a specific time in intervals.
    pub fn advance_to(&mut self, target_intervals: u64) {
        while self.time_intervals < target_intervals {
            self.tick();
        }
    }
}

/// Attestation metadata for fork choice tracking.
///
/// This is a lightweight representation of an attestation's position in the proto array.
#[derive(Debug, Clone, Default)]
pub struct ProtoAttestation {
    /// Index of the attested block in the proto array.
    pub index: usize,
    /// Slot of the attestation.
    pub slot: Slot,
    /// The full signed attestation (optional, for block inclusion).
    pub attestation: Option<SignedAttestation>,
}

impl ProtoAttestation {
    /// Creates a new ProtoAttestation.
    pub fn new(index: usize, slot: Slot, attestation: Option<SignedAttestation>) -> Self {
        Self {
            index,
            slot,
            attestation,
        }
    }
}

/// Tracks attestation state for a single validator.
///
/// Distinguishes between:
/// - `latest_known`: On-chain attestations (included in a block)
/// - `latest_new`: Gossip attestations (not yet included in a block)
/// - `applied_index`: The last index whose weight was applied to fork choice
#[derive(Debug, Clone, Default)]
pub struct AttestationTracker {
    /// Index of the last attestation whose weight was applied to fork choice.
    /// Used to compute weight deltas.
    pub applied_index: Option<usize>,

    /// Latest on-chain attestation (included in a block).
    /// These contribute to fork choice immediately.
    pub latest_known: Option<ProtoAttestation>,

    /// Latest gossip attestation (not yet included in a block).
    /// These are promoted to `latest_known` at specific intervals.
    pub latest_new: Option<ProtoAttestation>,
}

impl AttestationTracker {
    /// Creates a new empty AttestationTracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the tracker with an on-chain attestation.
    ///
    /// If the new attestation is newer than the current `latest_known`, it replaces it.
    /// If it's also newer than `latest_new`, clears `latest_new`.
    pub fn on_block_attestation(&mut self, proto_att: ProtoAttestation) {
        let new_slot = proto_att.slot;

        // Update latest_known if this is newer
        let should_update_known = self
            .latest_known
            .as_ref()
            .map(|k| new_slot > k.slot)
            .unwrap_or(true);

        if should_update_known {
            self.latest_known = Some(proto_att);
        }

        // Clear latest_new if the on-chain version is newer
        if let Some(ref new_att) = self.latest_new {
            if new_slot > new_att.slot {
                self.latest_new = None;
            }
        }
    }

    /// Updates the tracker with a gossip attestation.
    ///
    /// Only updates if the new attestation is newer than the current `latest_new`.
    pub fn on_gossip_attestation(&mut self, proto_att: ProtoAttestation) {
        let new_slot = proto_att.slot;

        let should_update = self
            .latest_new
            .as_ref()
            .map(|n| new_slot > n.slot)
            .unwrap_or(true);

        if should_update {
            self.latest_new = Some(proto_att);
        }
    }

    /// Promotes `latest_new` to `latest_known`.
    ///
    /// Called at specific intervals to accept pending gossip attestations.
    pub fn accept_new(&mut self) {
        if let Some(new_att) = self.latest_new.take() {
            self.latest_known = Some(new_att);
        }
    }

    /// Returns the attestation to use for weight calculation.
    ///
    /// If `from_known` is true, returns `latest_known`, otherwise returns `latest_new`.
    pub fn get_attestation(&self, from_known: bool) -> Option<&ProtoAttestation> {
        if from_known {
            self.latest_known.as_ref()
        } else {
            self.latest_new.as_ref()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixed_bytes::FixedBytesExtended;
    use types::Hash256;

    fn make_checkpoint(slot: u64) -> Checkpoint {
        Checkpoint {
            root: Hash256::zero(),
            slot: Slot(slot),
        }
    }

    #[test]
    fn test_fork_choice_store_new() {
        let checkpoint = make_checkpoint(0);
        let store = ForkChoiceStore::new(checkpoint.clone());

        assert_eq!(store.time_intervals, 0);
        assert_eq!(store.time_slots, 0);
        assert_eq!(store.latest_justified.slot, checkpoint.slot);
        assert_eq!(store.latest_finalized.slot, checkpoint.slot);
    }

    #[test]
    fn test_fork_choice_store_tick() {
        let checkpoint = make_checkpoint(0);
        let mut store = ForkChoiceStore::new(checkpoint);

        // Tick through one full slot
        assert_eq!(store.tick(), 1); // interval 1
        assert_eq!(store.time_slots, 0);

        assert_eq!(store.tick(), 2); // interval 2
        assert_eq!(store.time_slots, 0);

        assert_eq!(store.tick(), 3); // interval 3
        assert_eq!(store.time_slots, 0);

        assert_eq!(store.tick(), 0); // interval 0 of next slot
        assert_eq!(store.time_slots, 1);
    }

    #[test]
    fn test_fork_choice_store_update() {
        let checkpoint = make_checkpoint(0);
        let mut store = ForkChoiceStore::new(checkpoint);

        // Update with newer checkpoints
        let justified = make_checkpoint(5);
        let finalized = make_checkpoint(3);
        store.update(justified.clone(), finalized.clone());

        assert_eq!(store.latest_justified.slot.0, 5);
        assert_eq!(store.latest_finalized.slot.0, 3);

        // Update with older checkpoints (should not change)
        let old_justified = make_checkpoint(2);
        let old_finalized = make_checkpoint(1);
        store.update(old_justified, old_finalized);

        assert_eq!(store.latest_justified.slot.0, 5);
        assert_eq!(store.latest_finalized.slot.0, 3);
    }

    #[test]
    fn test_attestation_tracker_on_block() {
        let mut tracker = AttestationTracker::new();

        // First on-chain attestation
        let att1 = ProtoAttestation::new(1, Slot(5), None);
        tracker.on_block_attestation(att1);

        assert!(tracker.latest_known.is_some());
        assert_eq!(tracker.latest_known.as_ref().unwrap().slot.0, 5);

        // Newer on-chain attestation replaces it
        let att2 = ProtoAttestation::new(2, Slot(10), None);
        tracker.on_block_attestation(att2);

        assert_eq!(tracker.latest_known.as_ref().unwrap().slot.0, 10);

        // Older on-chain attestation does not replace
        let att3 = ProtoAttestation::new(3, Slot(7), None);
        tracker.on_block_attestation(att3);

        assert_eq!(tracker.latest_known.as_ref().unwrap().slot.0, 10);
    }

    #[test]
    fn test_attestation_tracker_accept_new() {
        let mut tracker = AttestationTracker::new();

        // Add gossip attestation
        let att = ProtoAttestation::new(1, Slot(5), None);
        tracker.on_gossip_attestation(att);

        assert!(tracker.latest_new.is_some());
        assert!(tracker.latest_known.is_none());

        // Accept new
        tracker.accept_new();

        assert!(tracker.latest_new.is_none());
        assert!(tracker.latest_known.is_some());
        assert_eq!(tracker.latest_known.as_ref().unwrap().slot.0, 5);
    }
}
