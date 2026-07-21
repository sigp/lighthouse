//! Per-validator committee slot assignments, resolved on demand from the committee-cache
//! shufflings covering the `[current-2, current]` epoch window of a state.

use std::sync::Arc;

use safe_arith::SafeArith;

use crate::{
    attestation::AttestationShufflingId,
    core::{ChainSpec, Epoch, EthSpec, Hash256, RelativeEpoch, Slot},
    state::{BeaconState, BeaconStateError, CommitteeCache},
};

/// One of the three epochs the assignment window covers.
#[derive(Debug, Clone, Copy)]
enum WindowEpoch {
    PrevPrev,
    Previous,
    Current,
}

impl WindowEpoch {
    fn epoch<E: EthSpec>(self, state: &BeaconState<E>) -> Epoch {
        match self {
            Self::PrevPrev => state.previous_epoch().saturating_sub(1u64),
            Self::Previous => state.previous_epoch(),
            Self::Current => state.current_epoch(),
        }
    }

    /// `None` for `PrevPrev`, which has no `RelativeEpoch` in the state.
    fn relative_epoch(self) -> Option<RelativeEpoch> {
        match self {
            Self::Current => Some(RelativeEpoch::Current),
            Self::Previous => Some(RelativeEpoch::Previous),
            Self::PrevPrev => None,
        }
    }

    fn shuffling_id<E: EthSpec>(
        self,
        state: &BeaconState<E>,
    ) -> Result<AttestationShufflingId, BeaconStateError> {
        // Block root is only used for genesis so we use zero.
        let block_root = Hash256::ZERO;
        if let Some(relative_epoch) = self.relative_epoch() {
            return AttestationShufflingId::new(block_root, state, relative_epoch);
        }
        let epoch = self.epoch(state);
        let shuffling_decision_slot = epoch
            .saturating_sub(1u64)
            .start_slot(E::slots_per_epoch())
            .saturating_sub(1u64);
        let shuffling_decision_root = state
            .get_block_root(shuffling_decision_slot)
            .copied()
            .unwrap_or(block_root);
        Ok(AttestationShufflingId::from_components(
            epoch,
            shuffling_decision_root,
        ))
    }

    /// `Current`/`Previous` come from the state's caches when built; `PrevPrev` is always
    /// recomputed.
    fn committee_cache<E: EthSpec>(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Arc<CommitteeCache>, BeaconStateError> {
        if let Some(relative_epoch) = self.relative_epoch()
            && let Ok(cache) = state.committee_cache(relative_epoch)
        {
            return Ok(cache.clone());
        }
        state.initialize_committee_cache(self.epoch(state), spec)
    }
}

#[derive(Debug, Clone)]
struct SlotAssignment {
    key: AttestationShufflingId,
    committee_cache: Arc<CommitteeCache>,
    epoch_start_slot: Slot,
    epoch_end_slot: Slot,
}

impl SlotAssignment {
    /// Re-uses a matching cache from `prev` when the shuffling is unchanged.
    fn new<E: EthSpec>(
        state: &BeaconState<E>,
        window_epoch: WindowEpoch,
        spec: &ChainSpec,
        prev: Option<&SlotAssignments>,
    ) -> Result<Self, BeaconStateError> {
        let key = window_epoch.shuffling_id(state)?;
        if let Some(existing) =
            prev.and_then(|prev| prev.assignments.iter().find(|existing| existing.key == key))
        {
            return Ok(existing.clone());
        }
        let epoch = window_epoch.epoch(state);
        Ok(Self {
            key,
            committee_cache: window_epoch.committee_cache(state, spec)?,
            epoch_start_slot: epoch.start_slot(E::slots_per_epoch()),
            epoch_end_slot: epoch.end_slot(E::slots_per_epoch()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SlotAssignments {
    /// Committee caches in epoch ascending order (current - 2, current - 1, current).
    assignments: [SlotAssignment; 3],
}

impl SlotAssignments {
    /// Build the `[current-2, current]` committee caches for `state`, re-using unchanged
    /// epochs from `prev`.
    pub fn new<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
        prev: Option<&Self>,
    ) -> Result<Self, BeaconStateError> {
        Ok(Self {
            assignments: [
                SlotAssignment::new(state, WindowEpoch::PrevPrev, spec, prev)?,
                SlotAssignment::new(state, WindowEpoch::Previous, spec, prev)?,
                SlotAssignment::new(state, WindowEpoch::Current, spec, prev)?,
            ],
        })
    }

    pub fn key(&self) -> &AttestationShufflingId {
        &self.assignments[2].key
    }

    /// True if `val_idx` attests in any window epoch at a slot within `[start, end]`.
    pub fn is_in_range(
        &self,
        val_idx: usize,
        start: Slot,
        end: Slot,
    ) -> Result<bool, BeaconStateError> {
        for assignment in &self.assignments {
            // Skip this epoch's cache if it has no overlap with the requested range.
            if assignment.epoch_end_slot < start || assignment.epoch_start_slot > end {
                continue;
            }
            if assigned_slot(
                &assignment.committee_cache,
                assignment.epoch_start_slot,
                val_idx,
            )?
            .is_some_and(|slot| slot >= start && slot <= end)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The slot `val_idx` attests in for `cache`'s epoch, or `None` if it has no duty.
/// Inverts the spec's `compute_committee` position ranges.
fn assigned_slot(
    cache: &CommitteeCache,
    epoch_start: Slot,
    val_idx: usize,
) -> Result<Option<Slot>, BeaconStateError> {
    let Some(position) = cache.shuffled_position(val_idx) else {
        return Ok(None);
    };
    let total = cache.epoch_committee_count()?;
    let committee = position
        .safe_mul(total)?
        .safe_add(total.safe_sub(1)?)?
        .safe_div(cache.active_validator_count())?;
    let offset = committee.safe_div(cache.committees_per_slot() as usize)?;
    Ok(Some(epoch_start.safe_add(offset as u64)?))
}
