//! Attestation weight per block for the previous, current and next slot, served by the custom
//! `attestation_weight` event topic.
//!
//! Every attestation this node verifies (gossip or HTTP API, single or aggregate) adds the
//! justified effective balance of its attesting validators to the block it votes for, counting each
//! validator once per slot. These are the balances fork choice weighs votes with. Votes are only
//! counted while the topic has a subscriber.
//!
//! ## Lock ordering
//!
//! `observe` may take the fork choice read lock while holding the tracker's lock, to copy the
//! justified balances. Never take the tracker's lock while holding a fork choice lock.

use bitvec::vec::BitVec;
use eth2::types::{BlockAttestationWeight, SlotAttestationWeight, SseAttestationWeight};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use types::{Checkpoint, Hash256, Slot};

/// A verified attestation, as the tracker needs it.
pub struct AttestationVote<'a> {
    pub slot: Slot,
    pub block_root: Hash256,
    /// See `BlockAttestationWeight::payload_present`.
    pub payload_present: Option<bool>,
    pub attesting_indices: &'a [u64],
}

/// Fork choice's justified balances for one justified checkpoint.
pub struct CheckpointBalances {
    pub checkpoint: Checkpoint,
    /// Per validator index, zero for a validator that is slashed or not active, as in fork choice.
    pub effective_balances: Vec<u64>,
    /// The justified total effective balance divided by slots per epoch.
    pub committee_weight_gwei: u64,
}

#[derive(Default)]
pub struct AttestationWeightTracker {
    subscribers: AtomicUsize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Bumped on every change, so a receiver only sends changed weights.
    version: u64,
    balances: Option<CheckpointBalances>,
    /// The previous, current and next slot. Late votes for the previous slot still count in fork
    /// choice, and votes for the next slot can arrive up to the gossip clock disparity early.
    slots: BTreeMap<Slot, SlotWeights>,
}

#[derive(Default)]
struct SlotWeights {
    observed_validators: BitVec,
    voters: u64,
    blocks: Vec<BlockAttestationWeight>,
}

/// A subscriber to the tracker.
pub struct AttestationWeightReceiver {
    tracker: Arc<AttestationWeightTracker>,
    sent_version: Option<u64>,
}

impl AttestationWeightReceiver {
    /// The weights, if they changed since this receiver last returned them. Returns `None` rather
    /// than waiting when the tracker is busy, as it is called from an async task.
    pub fn changed_weights(&mut self) -> Option<SseAttestationWeight> {
        let inner = self.tracker.inner.try_lock()?;
        if self.sent_version == Some(inner.version) || inner.slots.is_empty() {
            return None;
        }
        let weights = inner.weights()?;
        self.sent_version = Some(inner.version);
        Some(weights)
    }
}

impl Drop for AttestationWeightReceiver {
    fn drop(&mut self) {
        // Don't block the connection task on the lock. If it is held, the next subscriber resets
        // the tracker.
        if self.tracker.subscribers.fetch_sub(1, Ordering::Relaxed) == 1
            && let Some(mut inner) = self.tracker.inner.try_lock()
            && !self.tracker.has_subscribers()
        {
            inner.reset();
        }
    }
}

impl Inner {
    /// Forget all votes and balances.
    fn reset(&mut self) {
        *self = Inner {
            // Keep the version moving, so no receiver mistakes the new weights for ones it sent.
            version: self.version.wrapping_add(1),
            ..Inner::default()
        };
    }

    fn weights(&self) -> Option<SseAttestationWeight> {
        Some(SseAttestationWeight {
            committee_weight_gwei: self.balances.as_ref()?.committee_weight_gwei,
            slots: self
                .slots
                .iter()
                .map(|(&slot, slot_weights)| SlotAttestationWeight {
                    slot,
                    voters: slot_weights.voters,
                    weights: slot_weights.blocks.clone(),
                })
                .collect(),
        })
    }
}

impl AttestationWeightTracker {
    pub fn has_subscribers(&self) -> bool {
        self.subscribers.load(Ordering::Relaxed) > 0
    }

    pub fn subscribe(self: &Arc<Self>) -> AttestationWeightReceiver {
        let mut inner = self.inner.lock();
        if self.subscribers.fetch_add(1, Ordering::Relaxed) == 0 {
            inner.reset();
        }
        AttestationWeightReceiver {
            tracker: self.clone(),
            sent_version: None,
        }
    }

    /// Count the attesting validators of verified attestations. `load_balances` is called when the
    /// balances in use are not for `justified_checkpoint`.
    pub fn observe<'a>(
        &self,
        votes: impl IntoIterator<Item = AttestationVote<'a>>,
        current_slot: Slot,
        justified_checkpoint: Checkpoint,
        load_balances: impl FnOnce() -> Option<CheckpointBalances>,
    ) {
        let mut inner = self.inner.lock();
        // The last subscriber may have unsubscribed since the caller checked.
        if !self.has_subscribers() {
            return;
        }
        let Inner {
            version,
            balances,
            slots,
        } = &mut *inner;
        let mut changed = false;
        if balances.as_ref().map(|balances| balances.checkpoint) != Some(justified_checkpoint)
            && let Some(loaded) = load_balances()
        {
            *balances = Some(loaded);
            changed = true;
        }
        let Some(balances) = balances.as_ref() else {
            return;
        };

        let previous_slot = current_slot.saturating_sub(1u64);
        let next_slot = current_slot.saturating_add(1u64);
        let len_before = slots.len();
        slots.retain(|&slot, _| slot >= previous_slot);
        changed |= slots.len() != len_before;

        for vote in votes {
            if vote.slot < previous_slot || vote.slot > next_slot {
                continue;
            }
            let slot_weights = slots.entry(vote.slot).or_default();
            let mut added_gwei = 0u64;
            for &validator_index in vote.attesting_indices {
                let index = validator_index as usize;
                if slot_weights.observed_validators.len() <= index {
                    slot_weights
                        .observed_validators
                        .resize(index.saturating_add(1), false);
                }
                if slot_weights.observed_validators.replace(index, true) {
                    continue;
                }
                slot_weights.voters = slot_weights.voters.saturating_add(1);
                changed = true;
                // A validator activated after the justified epoch has no balance, as in fork choice.
                let balance = balances.effective_balances.get(index).copied().unwrap_or(0);
                added_gwei = added_gwei.saturating_add(balance);
            }
            if added_gwei == 0 {
                continue;
            }
            match slot_weights.blocks.iter_mut().find(|block| {
                block.block_root == vote.block_root && block.payload_present == vote.payload_present
            }) {
                Some(block) => block.weight_gwei = block.weight_gwei.saturating_add(added_gwei),
                None => slot_weights.blocks.push(BlockAttestationWeight {
                    block_root: vote.block_root,
                    payload_present: vote.payload_present,
                    weight_gwei: added_gwei,
                }),
            }
        }
        if changed {
            *version = version.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use types::Epoch;

    const GWEI_32_ETH: u64 = 32_000_000_000;

    fn checkpoint(epoch: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::new(epoch),
            root: Hash256::ZERO,
        }
    }

    fn vote(slot: u64, root: u64, indices: &[u64]) -> AttestationVote<'_> {
        AttestationVote {
            slot: Slot::new(slot),
            block_root: Hash256::from_low_u64_be(root),
            payload_present: None,
            attesting_indices: indices,
        }
    }

    /// Observe with 64 validators of 32 ETH at justified epoch 0.
    fn observe<'a>(
        tracker: &AttestationWeightTracker,
        votes: impl IntoIterator<Item = AttestationVote<'a>>,
        current_slot: u64,
    ) {
        tracker.observe(votes, Slot::new(current_slot), checkpoint(0), || {
            Some(CheckpointBalances {
                checkpoint: checkpoint(0),
                effective_balances: vec![GWEI_32_ETH; 64],
                committee_weight_gwei: 100,
            })
        });
    }

    fn slot_weights(tracker: &AttestationWeightTracker) -> Vec<SlotAttestationWeight> {
        tracker
            .inner
            .lock()
            .weights()
            .map(|weights| weights.slots)
            .unwrap_or_default()
    }

    #[test]
    fn counts_validator_once() {
        let tracker = Arc::new(AttestationWeightTracker::default());
        let _receiver = tracker.subscribe();
        observe(&tracker, [vote(1, 1, &[3])], 1);
        // index 100 is beyond the justified balances, like a validator activated since
        observe(&tracker, [vote(1, 1, &[1, 2, 3, 100])], 1);
        let weights = slot_weights(&tracker);
        assert_eq!(weights[0].voters, 4);
        assert_eq!(weights[0].weights[0].weight_gwei, 3 * GWEI_32_ETH);
    }

    #[test]
    fn retains_previous_current_and_next_slot() {
        let tracker = Arc::new(AttestationWeightTracker::default());
        let _receiver = tracker.subscribe();
        observe(
            &tracker,
            [vote(1, 1, &[1]), vote(2, 2, &[1]), vote(3, 3, &[1])],
            2,
        );
        assert_eq!(slot_weights(&tracker).len(), 3);
        // at slot 3, slot 1 is too old, and so is a late vote for it
        observe(&tracker, [vote(1, 1, &[2])], 3);
        let slots = slot_weights(&tracker)
            .iter()
            .map(|weights| weights.slot.as_u64())
            .collect::<Vec<_>>();
        assert_eq!(slots, [2, 3]);
    }

    #[test]
    fn splits_by_payload_present() {
        let tracker = Arc::new(AttestationWeightTracker::default());
        let _receiver = tracker.subscribe();
        let full = AttestationVote {
            payload_present: Some(true),
            ..vote(1, 1, &[1, 2])
        };
        let empty = AttestationVote {
            payload_present: Some(false),
            ..vote(1, 1, &[3])
        };
        observe(&tracker, [full, empty], 1);
        let blocks = &slot_weights(&tracker)[0].weights;
        assert_eq!(blocks[0].payload_present, Some(true));
        assert_eq!(blocks[0].weight_gwei, 2 * GWEI_32_ETH);
        assert_eq!(blocks[1].payload_present, Some(false));
        assert_eq!(blocks[1].weight_gwei, GWEI_32_ETH);
    }

    #[test]
    fn loads_balances_when_justified_checkpoint_changes() {
        let tracker = Arc::new(AttestationWeightTracker::default());
        let _receiver = tracker.subscribe();
        let mut loads = 0;
        for justified_epoch in [0, 0, 1] {
            tracker.observe([], Slot::new(1), checkpoint(justified_epoch), || {
                loads += 1;
                Some(CheckpointBalances {
                    checkpoint: checkpoint(justified_epoch),
                    effective_balances: vec![],
                    committee_weight_gwei: 100,
                })
            });
        }
        assert_eq!(loads, 2);
    }

    #[test]
    fn sends_only_changes_while_subscribed() {
        let tracker = Arc::new(AttestationWeightTracker::default());
        observe(&tracker, [vote(1, 1, &[1])], 1);
        assert!(slot_weights(&tracker).is_empty());

        let mut receiver = tracker.subscribe();
        observe(&tracker, [vote(1, 1, &[1])], 1);
        assert!(receiver.changed_weights().is_some());
        // a validator already counted changes nothing
        observe(&tracker, [vote(1, 1, &[1])], 1);
        assert!(receiver.changed_weights().is_none());
        drop(receiver);
        assert!(slot_weights(&tracker).is_empty());
    }
}
