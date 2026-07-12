//! Committee slot assignments for the Fast Confirmation Rule, resolved on demand from the
//! committee-cache shufflings covering the `[current-2, current]` epoch window.

use crate::Error;
use safe_arith::SafeArith;
use std::sync::Arc;
use types::{
    AttestationShufflingId, BeaconState, ChainSpec, CommitteeCache, Epoch, EthSpec, Hash256,
    RelativeEpoch, Slot,
};

/// One of the three epochs the FCR examines for committee assignments, relative to a beacon
/// state's current epoch.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WindowEpoch {
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

    fn shuffling_id<E: EthSpec>(
        self,
        state: &BeaconState<E>,
    ) -> Result<AttestationShufflingId, Error> {
        // Block root is only used for genesis so we use zero.
        let block_root = Hash256::ZERO;
        match self {
            Self::Current => AttestationShufflingId::new(block_root, state, RelativeEpoch::Current)
                .map_err(Error::AttestationShufflingIdError),
            Self::Previous => {
                AttestationShufflingId::new(block_root, state, RelativeEpoch::Previous)
                    .map_err(Error::AttestationShufflingIdError)
            }
            Self::PrevPrev => {
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
        }
    }

    /// The committee cache for this window position. `Current`/`Previous` are read from the state's
    /// caches; `PrevPrev` has no cached slot in the state, so its shuffling is recomputed.
    fn committee_cache<E: EthSpec>(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Arc<CommitteeCache>, Error> {
        match self {
            Self::Current => Ok(state
                .committee_cache(RelativeEpoch::Current)
                .map_err(Error::CommitteeCacheError)?
                .clone()),
            Self::Previous => Ok(state
                .committee_cache(RelativeEpoch::Previous)
                .map_err(Error::CommitteeCacheError)?
                .clone()),
            Self::PrevPrev => state
                .initialize_committee_cache(self.epoch(state), spec)
                .map_err(Error::CommitteeCacheError),
        }
    }
}

#[derive(Debug, Clone)]
struct SlotAssignment {
    key: AttestationShufflingId,
    committee_cache: Arc<CommitteeCache>,
    /// Start slot of `key.shuffling_epoch` cached for quick access.
    epoch_start_slot: Slot,
    /// End slot of `key.shuffling_epoch` cached for quick access.
    epoch_end_slot: Slot,
}

/// The attestation shuffling id for `window_epoch` relative to `state`.
pub(crate) fn attestation_shuffling_id<E: EthSpec>(
    state: &BeaconState<E>,
    window_epoch: WindowEpoch,
) -> Result<AttestationShufflingId, Error> {
    window_epoch.shuffling_id(state)
}

impl SlotAssignment {
    /// Build the assignment for `window_epoch` relative to `state`, re-using a matching cache from
    /// `prev` when its shuffling is unchanged (a rebuild rotating the window down an epoch).
    fn new<E: EthSpec>(
        state: &BeaconState<E>,
        window_epoch: WindowEpoch,
        spec: &ChainSpec,
        prev: Option<&SlotAssignments>,
    ) -> Result<Self, Error> {
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
pub(crate) struct SlotAssignments {
    /// Committee caches in epoch ascending order (current - 2, current - 1, current).
    assignments: [SlotAssignment; 3],
}

impl SlotAssignments {
    /// Build the `[current-2, current]` committee caches for `state`. When `prev` is supplied (a
    /// rebuild triggered by a head change), any cache whose shuffling is unchanged is re-used from
    /// it rather than rebuilt — the common case where we just rotate the window down an epoch.
    pub(crate) fn new<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
        prev: Option<&Self>,
    ) -> Result<Self, Error> {
        Ok(Self {
            assignments: [
                SlotAssignment::new(state, WindowEpoch::PrevPrev, spec, prev)?,
                SlotAssignment::new(state, WindowEpoch::Previous, spec, prev)?,
                SlotAssignment::new(state, WindowEpoch::Current, spec, prev)?,
            ],
        })
    }

    pub(crate) fn key(&self) -> &AttestationShufflingId {
        &self.assignments[2].key
    }

    /// True if `val_idx` attests in any window epoch at a slot within `[start, end]`.
    pub(crate) fn is_in_range(
        &self,
        val_idx: usize,
        start: Slot,
        end: Slot,
    ) -> Result<bool, Error> {
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

/// The committee slot `val_idx` attests in for `cache`'s epoch, or `None` if it has no duty.
/// Inverts the spec's `compute_committee` position ranges: the committee for shuffled position `p`
/// is `(p * count + count - 1) / len`, mapped to a slot via `committees_per_slot`.
fn assigned_slot(
    cache: &CommitteeCache,
    epoch_start: Slot,
    val_idx: usize,
) -> Result<Option<Slot>, Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use state_processing::per_slot_processing;
    use types::{MinimalEthSpec, Validator};

    type E = MinimalEthSpec;

    fn genesis_state(n: usize) -> (BeaconState<E>, types::ChainSpec) {
        let spec = E::default_spec();
        let mut state = BeaconState::new(0, Default::default(), &spec);
        for _ in 0..n {
            state
                .validators_mut()
                .push(Validator {
                    effective_balance: spec.max_effective_balance,
                    activation_epoch: Epoch::new(0),
                    exit_epoch: spec.far_future_epoch,
                    withdrawable_epoch: spec.far_future_epoch,
                    ..Default::default()
                })
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

    fn advance_state(state: &mut BeaconState<E>, target: Slot, spec: &types::ChainSpec) {
        while state.slot() < target {
            per_slot_processing(state, None, spec).expect("advance slot");
        }
        state
            .build_all_committee_caches(spec)
            .expect("committee caches");
    }

    #[test]
    fn builds_from_genesis_state() {
        let (state, spec) = genesis_state(64);
        SlotAssignments::new::<E>(&state, &spec, None).expect("builds from genesis state");
    }

    #[test]
    fn every_validator_attests_once_in_current_epoch() {
        let (mut state, spec) = genesis_state(64);
        let spe = E::slots_per_epoch();
        let start = Slot::new(spe * 2);
        advance_state(&mut state, start, &spec);
        let sa = SlotAssignments::new::<E>(&state, &spec, None).expect("build");

        let end = Slot::new(spe * 2 + spe - 1);
        for val_idx in 0..state.validators().len() {
            assert!(
                sa.is_in_range(val_idx, start, end).unwrap(),
                "validator {val_idx} missing epoch 2 assignment"
            );
        }
    }

    #[test]
    fn is_in_range_returns_false_for_uncovered_epochs() {
        let (state, spec) = genesis_state(64);
        let sa = SlotAssignments::new::<E>(&state, &spec, None).expect("build");
        let far = Slot::new(E::slots_per_epoch() * 5);
        for val_idx in 0..state.validators().len() {
            assert!(!sa.is_in_range(val_idx, far, far).unwrap());
        }
    }
}
