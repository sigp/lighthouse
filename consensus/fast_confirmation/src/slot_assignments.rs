//! Per-validator committee slot assignment table used by the Fast Confirmation Rule.

use crate::Error;
use safe_arith::SafeArith;
use types::{BeaconState, EthSpec, Hash256, RelativeEpoch, Slot};

/// Per-validator committee slot assignments across a 3-epoch window.
///
/// Each active validator is assigned to exactly one committee slot per epoch.
/// This structure tracks those assignments for epochs `[current-1, current, current+1]`,
/// stored as a flat `Vec<Slot>` with stride 3 for cache-friendly iteration over all
/// validators.
///
/// # Layout
///
/// ```text
///                    previous   current    next
/// validator 0:       slot_a     slot_b     slot_c
/// validator 1:       slot_d     slot_e     slot_f
/// ...
/// ```
///
/// Stored flat: `[slot_a, slot_b, slot_c, slot_d, slot_e, slot_f, ...]`
///
/// Access: `slots[validator_index * 3 + column]` where column 0/1/2 is the
/// `[previous, current, next]` epoch of the state it was built from.
///
/// # Sentinel
///
/// `UNSET_SLOT` (`Slot(u64::MAX)`) marks uninitialized entries. Reading an unset
/// slot via `is_in_range` returns an error, catching rebuild bugs early.
#[derive(Clone, Debug)]
pub(crate) struct SlotAssignments {
    /// Length is `validator_count * 3` (stride-3 layout, see the type-level docs).
    slots: Vec<Slot>,
    /// Shuffling decision root the table was built for. The owner rebuilds when it changes.
    dependent_root: Hash256,
}

/// Number of epoch columns in the slot assignment table.
const NUM_EPOCH_COLUMNS: usize = 3;

/// Sentinel value for unset slot assignments. Using `u64::MAX` instead of `Slot(0)`
/// avoids ambiguity with genesis slot 0 and allows hard error detection on read.
pub const UNSET_SLOT: Slot = Slot::new(u64::MAX);

impl SlotAssignments {
    /// Build assignments from a beacon state, tagged with the dependent root it derives for the
    /// state's current epoch.
    ///
    /// Computes the 3-epoch window `[previous, current, next]` and fills assignments from the
    /// state's committee caches; validators with no committee duty in a column are left `UNSET_SLOT`.
    /// The owner rebuilds (replaces) the table whenever that dependent root changes.
    ///
    /// # Performance
    ///
    /// Instead of calling `get_attestation_duties()` per validator (O(N × C) where C =
    /// committees per epoch), we iterate the committee cache's shuffled list directly and
    /// derive slot from shuffled position in O(1). Total cost: O(N) per epoch column.
    pub(crate) fn new<E: EthSpec>(state: &BeaconState<E>) -> Result<Self, Error> {
        let dependent_root = crate::dependent_root::<E>(state, state.current_epoch())?;
        let validator_count = state.validators().len();
        let total_columns = validator_count.safe_mul(NUM_EPOCH_COLUMNS)?;
        let mut new_slots = vec![UNSET_SLOT; total_columns];

        // Fill from the committee caches by iterating each epoch's shuffled list directly.
        // This is O(active_validators) per epoch instead of O(validators × committees).
        for (col, relative_epoch, epoch) in [
            (0, RelativeEpoch::Previous, state.previous_epoch()),
            (1, RelativeEpoch::Current, state.current_epoch()),
            (2, RelativeEpoch::Next, state.current_epoch().safe_add(1)?),
        ] {
            let committee_cache = state
                .committee_cache(relative_epoch)
                .map_err(|e| Error::CommitteeCacheUninitialized(format!("{e:?}")))?;

            let shuffling = committee_cache.shuffling();
            let committees_per_slot = committee_cache.committees_per_slot() as usize;
            let epoch_start = epoch.start_slot(E::slots_per_epoch());

            // Each position in the shuffled list maps to a committee, which maps to a slot.
            // committee_index_in_epoch = position * total_committees / shuffling_len
            // slot_offset = committee_index_in_epoch / committees_per_slot
            let total_committees = committees_per_slot.safe_mul(E::slots_per_epoch() as usize)?;
            let shuffling_len = shuffling.len();

            for (position, &val_idx) in shuffling.iter().enumerate() {
                let committee_index = position
                    .safe_mul(total_committees)?
                    .safe_div(shuffling_len)?;
                let slot_offset = committee_index.safe_div(committees_per_slot)?;
                let slot = epoch_start.safe_add(slot_offset as u64)?;
                if val_idx < validator_count {
                    let idx = val_idx.safe_mul(NUM_EPOCH_COLUMNS)?.safe_add(col)?;
                    *new_slots.get_mut(idx).ok_or(Error::IndexOutOfBounds(idx))? = slot;
                }
            }
        }

        Ok(Self {
            slots: new_slots,
            dependent_root,
        })
    }

    /// Shuffling decision root this table was built for.
    pub(crate) fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    /// Get the assigned slot for a validator in a given column (0, 1, or 2).
    fn get(&self, val_idx: usize, col: usize) -> Option<Slot> {
        let idx = val_idx
            .safe_mul(NUM_EPOCH_COLUMNS)
            .ok()?
            .safe_add(col)
            .ok()?;
        self.slots.get(idx).copied()
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
            if slot == UNSET_SLOT {
                continue;
            }
            if slot >= start_slot && slot <= end_slot {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_processing::per_slot_processing;
    use types::{Epoch, MinimalEthSpec};

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
            .build_all_committee_caches(&spec)
            .expect("committee caches");

        (state, spec)
    }

    /// Advance a state to a given slot, rebuilding committee caches.
    fn advance_state(state: &mut BeaconState<E>, target_slot: Slot, spec: &types::ChainSpec) {
        while state.slot() < target_slot {
            per_slot_processing(state, None, spec).expect("should advance slot");
        }
        state
            .build_all_committee_caches(spec)
            .expect("committee caches");
    }

    #[test]
    fn builds_from_genesis_state() {
        let (state, _spec) = genesis_state(64);
        SlotAssignments::new::<E>(&state).expect("builds from genesis state");
    }

    #[test]
    fn rebuild_populates_assignments_for_correct_epochs() {
        let (mut state, spec) = genesis_state(64);

        // Advance state to epoch 2.
        let epoch_2_start = E::slots_per_epoch() * 2;
        advance_state(&mut state, Slot::new(epoch_2_start), &spec);

        let sa = SlotAssignments::new::<E>(&state).expect("build should succeed");

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

        // State at epoch 0, covers epochs [0, 0, 1].
        let sa = SlotAssignments::new::<E>(&state).expect("should build");

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
