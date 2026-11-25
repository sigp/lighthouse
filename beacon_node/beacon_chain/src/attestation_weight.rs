//! Attestation weight per block for the previous, current and next slot, served by
//! `GET lighthouse/attestation_weight`.
//!
//! Every attestation this node verifies (gossip or HTTP API, single or aggregate) adds the
//! justified effective balance of its attesting validators to the block it votes for, counting each
//! validator once per slot. These are the balances fork choice weighs votes with. Fork choice only
//! applies a vote after its slot, so it can't give this weight during the slot.
//!
//! ## Lock ordering
//!
//! `observe` and `weights` may take the fork choice read lock while holding the tracker's lock, to
//! copy the justified balances. Never take the tracker's lock while holding a fork choice lock.

use bitvec::vec::BitVec;
use eth2::lighthouse::{AttestationWeights, BlockAttestationWeight, SlotAttestationWeight};
use parking_lot::Mutex;
use std::collections::BTreeMap;
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
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    balances: Option<CheckpointBalances>,
    /// The previous, current and next slot: late votes for the previous slot, and votes for the
    /// next slot that arrive up to the gossip clock disparity early.
    slots: BTreeMap<Slot, SlotWeights>,
}

#[derive(Default)]
struct SlotWeights {
    observed_validators: BitVec,
    voters: u64,
    blocks: Vec<BlockAttestationWeight>,
}

impl Inner {
    /// Load the balances if there are none or `justified_checkpoint` is newer than theirs, and
    /// forget slots before the previous slot. Returns the balances and the slots.
    fn update(
        &mut self,
        current_slot: Slot,
        justified_checkpoint: Checkpoint,
        load_balances: impl FnOnce() -> CheckpointBalances,
    ) -> (&CheckpointBalances, &mut BTreeMap<Slot, SlotWeights>) {
        let previous_slot = current_slot.saturating_sub(1u64);
        self.slots.retain(|&slot, _| slot >= previous_slot);
        let balances = match self.balances.take() {
            Some(balances) if justified_checkpoint.epoch <= balances.checkpoint.epoch => balances,
            _ => load_balances(),
        };
        (self.balances.insert(balances), &mut self.slots)
    }
}

impl AttestationWeightTracker {
    /// The weights for the previous, current and next slot. Like `observe`, this forgets older
    /// slots and loads the balances when `justified_checkpoint` is newer than theirs.
    pub fn weights(
        &self,
        current_slot: Slot,
        justified_checkpoint: Checkpoint,
        load_balances: impl FnOnce() -> CheckpointBalances,
    ) -> AttestationWeights {
        let mut inner = self.inner.lock();
        let (balances, slots) = inner.update(current_slot, justified_checkpoint, load_balances);
        AttestationWeights {
            committee_weight_gwei: balances.committee_weight_gwei,
            slots: slots
                .iter()
                .map(|(&slot, slot_weights)| SlotAttestationWeight {
                    slot,
                    voters: slot_weights.voters,
                    weights: slot_weights.blocks.clone(),
                })
                .collect(),
        }
    }

    /// Count the attesting validators of verified attestations.
    pub fn observe<'a>(
        &self,
        votes: impl IntoIterator<Item = AttestationVote<'a>>,
        current_slot: Slot,
        justified_checkpoint: Checkpoint,
        load_balances: impl FnOnce() -> CheckpointBalances,
    ) {
        let mut inner = self.inner.lock();
        let (balances, slots) = inner.update(current_slot, justified_checkpoint, load_balances);

        let previous_slot = current_slot.saturating_sub(1u64);
        let next_slot = current_slot.saturating_add(1u64);
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

    /// 64 validators of 32 ETH at justified epoch 0.
    fn balances() -> CheckpointBalances {
        CheckpointBalances {
            checkpoint: checkpoint(0),
            effective_balances: vec![GWEI_32_ETH; 64],
            committee_weight_gwei: 100,
        }
    }

    fn observe<'a>(
        tracker: &AttestationWeightTracker,
        votes: impl IntoIterator<Item = AttestationVote<'a>>,
        current_slot: u64,
    ) {
        tracker.observe(votes, Slot::new(current_slot), checkpoint(0), balances);
    }

    fn slot_weights(
        tracker: &AttestationWeightTracker,
        current_slot: u64,
    ) -> Vec<SlotAttestationWeight> {
        tracker
            .weights(Slot::new(current_slot), checkpoint(0), balances)
            .slots
    }

    #[test]
    fn counts_validator_once() {
        let tracker = AttestationWeightTracker::default();
        observe(&tracker, [vote(1, 1, &[3])], 1);
        // index 100 is beyond the justified balances, like a validator activated since
        observe(&tracker, [vote(1, 1, &[1, 2, 3, 100])], 1);
        let weights = slot_weights(&tracker, 1);
        assert_eq!(weights[0].voters, 4);
        assert_eq!(weights[0].weights[0].weight_gwei, 3 * GWEI_32_ETH);
    }

    #[test]
    fn retains_previous_current_and_next_slot() {
        let tracker = AttestationWeightTracker::default();
        observe(
            &tracker,
            [vote(1, 1, &[1]), vote(2, 2, &[1]), vote(3, 3, &[1])],
            2,
        );
        assert_eq!(slot_weights(&tracker, 2).len(), 3);
        // at slot 3, slot 1 is too old, and so is a late vote for it
        observe(&tracker, [vote(1, 1, &[2])], 3);
        let slots = slot_weights(&tracker, 3)
            .iter()
            .map(|weights| weights.slot.as_u64())
            .collect::<Vec<_>>();
        assert_eq!(slots, [2, 3]);
    }

    #[test]
    fn weights_forget_old_slots_without_new_votes() {
        let tracker = AttestationWeightTracker::default();
        observe(&tracker, [vote(1, 1, &[1])], 1);
        assert_eq!(slot_weights(&tracker, 2).len(), 1);
        assert!(slot_weights(&tracker, 3).is_empty());
    }

    #[test]
    fn weights_load_balances_before_any_vote() {
        let tracker = AttestationWeightTracker::default();
        let weights = tracker.weights(Slot::new(1), checkpoint(0), balances);
        assert_eq!(weights.committee_weight_gwei, 100);
        assert!(weights.slots.is_empty());
    }

    #[test]
    fn splits_by_payload_present() {
        let tracker = AttestationWeightTracker::default();
        let full = AttestationVote {
            payload_present: Some(true),
            ..vote(1, 1, &[1, 2])
        };
        let empty = AttestationVote {
            payload_present: Some(false),
            ..vote(1, 1, &[3])
        };
        observe(&tracker, [full, empty], 1);
        let blocks = &slot_weights(&tracker, 1)[0].weights;
        assert_eq!(blocks[0].payload_present, Some(true));
        assert_eq!(blocks[0].weight_gwei, 2 * GWEI_32_ETH);
        assert_eq!(blocks[1].payload_present, Some(false));
        assert_eq!(blocks[1].weight_gwei, GWEI_32_ETH);
    }

    #[test]
    fn loads_balances_when_justified_checkpoint_changes() {
        let tracker = AttestationWeightTracker::default();
        let mut loads = 0;
        // a caller that read the older checkpoint before the cached head moved doesn't reload
        for justified_epoch in [0, 0, 1, 0, 1] {
            tracker.observe([], Slot::new(1), checkpoint(justified_epoch), || {
                loads += 1;
                CheckpointBalances {
                    checkpoint: checkpoint(justified_epoch),
                    effective_balances: vec![],
                    committee_weight_gwei: 100,
                }
            });
        }
        assert_eq!(loads, 2);
    }

    #[test]
    fn loads_balances_once_while_fork_choice_is_ahead() {
        let tracker = AttestationWeightTracker::default();
        let mut loads = 0;
        // fork choice is at epoch 1 while the cached head is still at epoch 0, then catches up
        for justified_epoch in [0, 0, 1] {
            tracker.observe([], Slot::new(1), checkpoint(justified_epoch), || {
                loads += 1;
                CheckpointBalances {
                    checkpoint: checkpoint(1),
                    effective_balances: vec![],
                    committee_weight_gwei: 100,
                }
            });
        }
        assert_eq!(loads, 1);
    }
}
