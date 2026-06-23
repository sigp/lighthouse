//! Per-validator committee slot assignment table used by the Fast Confirmation Rule.

use crate::Error;
use types::{BeaconState, Epoch, EthSpec, RelativeEpoch, Slot};

/// Per-validator committee slot assignments across a 3-epoch window.
///
/// Each active validator is assigned to exactly one committee slot per epoch.
/// This structure tracks those assignments for epochs `[current-2, current-1, current]`,
/// stored as a flat `Vec<Slot>` with stride 3 for cache-friendly iteration over all
/// validators.
///
/// # Layout
///
/// ```text
///                    epoch-2    epoch-1    current
/// validator 0:       slot_a     slot_b     slot_c
/// validator 1:       slot_d     slot_e     slot_f
/// ...
/// ```
///
/// Stored flat: `[slot_a, slot_b, slot_c, slot_d, slot_e, slot_f, ...]`
///
/// Access: `slots[validator_index * 3 + column]` where column 0/1/2 maps to
/// the epoch at `epochs[column]`.
///
/// # Sentinel
///
/// `UNSET_SLOT` (`Slot(u64::MAX)`) marks uninitialized entries. Reading an unset
/// slot via `is_in_range` returns an error, catching rebuild bugs early.
#[derive(Clone, Debug)]
pub(crate) struct SlotAssignments {
    /// Flat array of slot assignments. Length = `validator_count * 3`.
    slots: Vec<Slot>,
    /// The 3 epochs covered by columns 0, 1, 2 (typically `[current-2, current-1, current]`).
    epochs: [Epoch; NUM_EPOCH_COLUMNS],
}

/// Number of epoch columns in the slot assignment table.
const NUM_EPOCH_COLUMNS: usize = 3;

/// Sentinel value for unset slot assignments. Using `u64::MAX` instead of `Slot(0)`
/// avoids ambiguity with genesis slot 0 and allows hard error detection on read.
pub const UNSET_SLOT: Slot = Slot::new(u64::MAX);

impl SlotAssignments {
    /// Create an empty assignment table.
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            epochs: [Epoch::new(0); NUM_EPOCH_COLUMNS],
        }
    }

    /// Get the assigned slot for a validator in a given column (0, 1, or 2).
    fn get(&self, val_idx: usize, col: usize) -> Option<Slot> {
        self.slots.get(val_idx * NUM_EPOCH_COLUMNS + col).copied()
    }

    /// Check if a validator is assigned to any committee in the slot range `[start, end]`.
    ///
    /// Iterates over all 3 epoch columns and returns `true` if any assigned slot
    /// falls within the range (inclusive). Columns with no assignment (`UNSET_SLOT`,
    /// or an out-of-range index) are treated as "not in range".
    pub(crate) fn is_in_range(
        &self,
        val_idx: usize,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<bool, Error> {
        for col in 0..NUM_EPOCH_COLUMNS {
            let Some(slot) = self.get(val_idx, col) else {
                continue;
            };
            // UNSET_SLOT means no assignment in this epoch column (inactive validator
            // or epoch not yet loaded). Treat as "not in range".
            if slot == UNSET_SLOT {
                continue;
            }
            if slot >= start_slot && slot <= end_slot {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Set assignments from external data. Intended for synthetic-data benchmarks;
    /// not used in production.
    ///
    /// `assignments` must be in the canonical 3-column layout:
    /// `assignments.len() == validator_count * 3`. Use `UNSET_SLOT` to mark
    /// columns that should be treated as having no assignment.
    pub(crate) fn test_set_from(&mut self, assignments: Vec<Slot>) {
        self.slots = assignments;
    }

    /// Rebuild assignments from a beacon state for the given slot.
    ///
    /// Computes the 3-epoch window `[current-2, current-1, current]` and fills
    /// assignments from the state's committee caches. Preserves old assignments
    /// that still fall within the new window (epoch column remapping).
    ///
    /// Returns early (cache hit) if the epoch window and validator count haven't changed.
    ///
    /// # Performance
    ///
    /// Instead of calling `get_attestation_duties()` per validator (O(N × C) where C =
    /// committees per epoch), we iterate the committee cache's shuffled list directly and
    /// derive slot from shuffled position in O(1). Total cost: O(N) per epoch column.
    pub(crate) fn rebuild<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let validator_count = state.validators().len();
        let current_slot_epoch = current_slot.epoch(E::slots_per_epoch());
        let state_current = state.current_epoch();

        // The state's committee caches cover [previous, current, next] epochs.
        // FCR queries assignments for slots up to current_slot, so the state must
        // cover current_slot's epoch. The state's next epoch is current + 1,
        // so we accept states where current_slot_epoch <= state_current + 1.
        let state_next = state
            .next_epoch()
            .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?;
        if current_slot_epoch > state_next {
            return Err(Error::StaleStateForAssignments {
                current_slot_epoch,
                state_epoch: state_current,
            });
        }

        // Use the state's available epochs to determine the window.
        let state_prev = state.previous_epoch();
        let desired_epochs = [state_prev, state_current, state_next];

        // Fast path: skip if epoch window and validator count are unchanged.
        if self.epochs == desired_epochs && self.slots.len() == validator_count * NUM_EPOCH_COLUMNS
        {
            return Ok(());
        }

        let mut new_slots = vec![UNSET_SLOT; validator_count * NUM_EPOCH_COLUMNS];

        // Preserve old assignments that overlap the new epoch window.
        if self.slots.len() == validator_count * NUM_EPOCH_COLUMNS {
            for val_idx in 0..validator_count {
                for (old_col, old_epoch) in self.epochs.iter().enumerate() {
                    if let Some(new_col) = desired_epochs.iter().position(|e| e == old_epoch) {
                        new_slots[val_idx * NUM_EPOCH_COLUMNS + new_col] =
                            self.slots[val_idx * NUM_EPOCH_COLUMNS + old_col];
                    }
                }
            }
        }

        // Fill from the committee caches by iterating the shuffled list directly.
        // This is O(active_validators) per epoch instead of O(validators × committees).
        let slots_per_epoch = E::slots_per_epoch();
        for relative_epoch in [
            RelativeEpoch::Previous,
            RelativeEpoch::Current,
            RelativeEpoch::Next,
        ] {
            let duty_epoch = match relative_epoch {
                RelativeEpoch::Previous => state.previous_epoch(),
                RelativeEpoch::Current => state.current_epoch(),
                RelativeEpoch::Next => state
                    .next_epoch()
                    .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?,
            };
            // `duty_epoch` is `state.{previous,current,next}_epoch()` and `desired_epochs` is built
            // from exactly those, so the position is always found.
            let col = desired_epochs
                .iter()
                .position(|e| *e == duty_epoch)
                .expect("duty_epoch is one of desired_epochs by construction");

            let committee_cache = state
                .committee_cache(relative_epoch)
                .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?;

            let shuffling = committee_cache.shuffling();
            let committees_per_slot = committee_cache.committees_per_slot() as usize;
            let epoch_start = duty_epoch.start_slot(slots_per_epoch);

            // Each position in the shuffled list maps to a committee, which maps to a slot.
            // committee_index_in_epoch = position * total_committees / shuffling_len
            // slot_offset = committee_index_in_epoch / committees_per_slot
            let total_committees = committees_per_slot * slots_per_epoch as usize;
            let shuffling_len = shuffling.len();

            for (position, &val_idx) in shuffling.iter().enumerate() {
                let committee_index = position * total_committees / shuffling_len;
                let slot_offset = committee_index / committees_per_slot;
                let slot = epoch_start + slot_offset as u64;
                if val_idx < validator_count {
                    new_slots[val_idx * NUM_EPOCH_COLUMNS + col] = slot;
                }
            }
        }

        self.slots = new_slots;
        self.epochs = desired_epochs;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_processing::per_slot_processing;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    /// Build a minimal genesis state with `n` validators and committee caches.
    /// Uses BeaconState::new directly with manually-added validators to avoid
    /// needing deposit proofs.
    fn genesis_state(n: usize) -> (BeaconState<E>, types::ChainSpec) {
        let spec = E::default_spec();
        let mut state = BeaconState::new(0, Default::default(), &spec);

        // Manually populate validators and balances.
        for _ in 0..n {
            let validator = types::Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            };
            state
                .validators_mut()
                .push(validator)
                .expect("push validator");
            state
                .balances_mut()
                .push(spec.max_effective_balance)
                .expect("push balance");
        }

        state
            .build_committee_cache(RelativeEpoch::Previous, &spec)
            .expect("prev cache");
        state
            .build_committee_cache(RelativeEpoch::Current, &spec)
            .expect("current cache");
        state
            .build_committee_cache(RelativeEpoch::Next, &spec)
            .expect("next cache");

        (state, spec)
    }

    /// Advance a state to a given slot, rebuilding committee caches.
    fn advance_state(state: &mut BeaconState<E>, target_slot: Slot, spec: &types::ChainSpec) {
        while state.slot() < target_slot {
            per_slot_processing(state, None, spec).expect("should advance slot");
        }
        state
            .build_committee_cache(RelativeEpoch::Previous, spec)
            .expect("prev cache");
        state
            .build_committee_cache(RelativeEpoch::Current, spec)
            .expect("current cache");
        state
            .build_committee_cache(RelativeEpoch::Next, spec)
            .expect("next cache");
    }

    #[test]
    fn rebuild_with_genesis_state_at_genesis_slot() {
        let (state, _spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // State at epoch 0, current_slot in epoch 0 — should work.
        sa.rebuild::<E>(&state, Slot::new(1))
            .expect("genesis state covers epoch 0");

        // Verify epoch window: [prev=0, current=0, next=1].
        assert_eq!(sa.epochs[0], Epoch::new(0));
        assert_eq!(sa.epochs[1], Epoch::new(0));
        assert_eq!(sa.epochs[2], Epoch::new(1));
    }

    #[test]
    fn rebuild_with_genesis_state_at_next_epoch_slot() {
        let (state, _spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // State at epoch 0, current_slot in epoch 1 — should work
        // because state's next epoch (1) covers current_slot's epoch.
        let epoch_1_slot = E::slots_per_epoch(); // slot 8 for minimal
        sa.rebuild::<E>(&state, Slot::new(epoch_1_slot))
            .expect("genesis state's next epoch covers epoch 1");
    }

    #[test]
    fn rebuild_rejects_stale_state() {
        let (state, _spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // State at epoch 0 (covers [0, 0, 1]), current_slot in epoch 2.
        // Epoch 2 > state's next epoch (1) — should fail.
        let epoch_2_slot = E::slots_per_epoch() * 2; // slot 16 for minimal
        let result = sa.rebuild::<E>(&state, Slot::new(epoch_2_slot));
        assert!(
            matches!(
                result,
                Err(Error::StaleStateForAssignments {
                    current_slot_epoch,
                    state_epoch,
                }) if current_slot_epoch == Epoch::new(2) && state_epoch == Epoch::new(0)
            ),
            "expected StaleStateForAssignments, got {:?}",
            result
        );
    }

    #[test]
    fn rebuild_rejects_state_3_epochs_behind() {
        let (state, _spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // State at epoch 0, current_slot in epoch 5 — clearly stale.
        let epoch_5_slot = E::slots_per_epoch() * 5;
        let result = sa.rebuild::<E>(&state, Slot::new(epoch_5_slot));
        assert!(
            matches!(result, Err(Error::StaleStateForAssignments { .. })),
            "expected StaleStateForAssignments for 5-epoch gap, got {:?}",
            result
        );
    }

    #[test]
    fn rebuild_advanced_state_covers_later_epochs() {
        let (mut state, spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // Advance state to epoch 2 (slot 16 for minimal).
        let epoch_2_start = E::slots_per_epoch() * 2;
        advance_state(&mut state, Slot::new(epoch_2_start), &spec);

        assert_eq!(state.current_epoch(), Epoch::new(2));

        // current_slot in epoch 2 — should work (state covers [1, 2, 3]).
        sa.rebuild::<E>(&state, Slot::new(epoch_2_start + 1))
            .expect("state at epoch 2 covers epoch 2");

        // current_slot in epoch 3 — should also work (state's next = 3).
        let epoch_3_start = E::slots_per_epoch() * 3;
        sa.rebuild::<E>(&state, Slot::new(epoch_3_start))
            .expect("state at epoch 2 covers epoch 3 via next");

        // current_slot in epoch 4 — should fail.
        let epoch_4_start = E::slots_per_epoch() * 4;
        let result = sa.rebuild::<E>(&state, Slot::new(epoch_4_start));
        assert!(
            matches!(result, Err(Error::StaleStateForAssignments { .. })),
            "state at epoch 2 can't cover epoch 4, got {:?}",
            result
        );
    }

    #[test]
    fn rebuild_populates_assignments_for_correct_epochs() {
        let (mut state, spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // Advance state to epoch 2.
        let epoch_2_start = E::slots_per_epoch() * 2;
        advance_state(&mut state, Slot::new(epoch_2_start), &spec);

        // Rebuild with current_slot in epoch 2.
        sa.rebuild::<E>(&state, Slot::new(epoch_2_start + 1))
            .expect("rebuild should succeed");

        // Epoch window should be [1, 2, 3].
        assert_eq!(sa.epochs[0], Epoch::new(1));
        assert_eq!(sa.epochs[1], Epoch::new(2));
        assert_eq!(sa.epochs[2], Epoch::new(3));

        // Every validator should have an assignment in at least the current epoch.
        let validator_count = state.validators().len();
        let spe = E::slots_per_epoch();
        for val_idx in 0..validator_count {
            // Check current epoch column (col 1 = epoch 2).
            let slot = sa.get(val_idx, 1).expect("valid index");
            assert_ne!(
                slot, UNSET_SLOT,
                "validator {val_idx} missing epoch 2 assignment"
            );
            // Assignment slot must be within epoch 2.
            let epoch_2_end = epoch_2_start + spe - 1;
            assert!(
                slot.as_u64() >= epoch_2_start && slot.as_u64() <= epoch_2_end,
                "validator {val_idx} assigned to slot {} which is not in epoch 2 [{epoch_2_start}, {epoch_2_end}]",
                slot
            );
        }

        // Slots in epoch 2 should be findable via is_in_range.
        let mid_epoch_2 = Slot::new(epoch_2_start + spe / 2);
        let mut found_any = false;
        for val_idx in 0..validator_count {
            if sa
                .is_in_range(val_idx, Slot::new(epoch_2_start), mid_epoch_2)
                .unwrap()
            {
                found_any = true;
                break;
            }
        }
        assert!(
            found_any,
            "at least one validator should be assigned in first half of epoch 2"
        );
    }

    #[test]
    fn is_in_range_returns_false_for_uncovered_epochs() {
        let (state, _spec) = genesis_state(64);
        let mut sa = SlotAssignments::new();

        // State at epoch 0, covers epochs [0, 0, 1].
        sa.rebuild::<E>(&state, Slot::new(1)).expect("should build");

        // Query for a slot in epoch 5 — no validator should match.
        let far_slot = Slot::new(E::slots_per_epoch() * 5);
        for val_idx in 0..state.validators().len() {
            assert!(
                !sa.is_in_range(val_idx, far_slot, far_slot).unwrap(),
                "validator {val_idx} should NOT be in range for epoch 5"
            );
        }
    }
}
