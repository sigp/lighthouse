//! Retains furthest empty-slot advances of the canonical head for reuse (#9530).
//!
//! Validator API handlers that need a state at the wall-clock epoch used to clone the
//! unadvanced head and advance through every empty epoch. During a prolonged outage that cost
//! grows as O(staleness) on every new epoch (and every concurrent caller).
//!
//! This cache keeps at most:
//! - one **partial** advance (invalid intermediate state roots; safe for shuffling / duties /
//!   attestation justified checkpoints), and
//! - one **complete** advance (valid state; safe for block production and `put_state`).
//!
//! Advances for the same head are serialized on a mutex so concurrent callers share one catch-up.
//! Head changes discard both entries.

use parking_lot::Mutex;
use tracing::debug;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// Furthest empty-slot advance retained for the current head.
#[derive(Clone)]
pub struct AdvancedHeadStateEntry<E: EthSpec> {
    pub head_block_root: Hash256,
    /// State root to feed the next `partial_state_advance` / `complete_state_advance` call.
    /// For partial advances this may be zero once the state is past the block header slot.
    pub state_root: Hash256,
    pub state: BeaconState<E>,
}

impl<E: EthSpec> AdvancedHeadStateEntry<E> {
    pub fn new(head_block_root: Hash256, state_root: Hash256, state: BeaconState<E>) -> Self {
        Self {
            head_block_root,
            state_root,
            state,
        }
    }
}

#[derive(Default)]
struct Inner<E: EthSpec> {
    partial: Option<AdvancedHeadStateEntry<E>>,
    complete: Option<AdvancedHeadStateEntry<E>>,
}

/// At most one partial and one complete retained advanced head state.
#[derive(Default)]
pub struct AdvancedHeadStateCache<E: EthSpec> {
    inner: Mutex<Inner<E>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceKind {
    /// Skip intermediate state roots (fast; state is not consensus-valid).
    Partial,
    /// Compute proper state roots (slower; state may be stored / used for block production).
    Complete,
}

impl<E: EthSpec> AdvancedHeadStateCache<E> {
    /// Discard retained states when the head changes (or for tests).
    pub fn invalidate(&self) {
        *self.inner.lock() = Inner::default();
    }

    fn store(slot: &mut Option<AdvancedHeadStateEntry<E>>, entry: AdvancedHeadStateEntry<E>) {
        let replace = match slot.as_ref() {
            None => true,
            Some(existing) if existing.head_block_root != entry.head_block_root => true,
            Some(existing) => entry.state.slot() >= existing.state.slot(),
        };
        if replace {
            *slot = Some(entry);
        }
    }

    /// Return a state for `head_block_root` advanced to at least `target_slot`.
    ///
    /// The mutex is held for the duration of a miss (including `advance`) so concurrent callers
    /// coalesce onto a single catch-up.
    ///
    /// **Partial** results must not be written to the hot store (`put_state`) — they have zero
    /// intermediate state roots. **Complete** results are safe to persist.
    pub fn get_or_advance_to<Err, Load, Advance>(
        &self,
        kind: AdvanceKind,
        head_block_root: Hash256,
        target_slot: Slot,
        load_starting_state: Load,
        advance: Advance,
    ) -> Result<AdvancedHeadStateEntry<E>, Err>
    where
        Load: FnOnce() -> Result<(Hash256, BeaconState<E>), Err>,
        Advance: FnOnce(BeaconState<E>, Hash256, Slot) -> Result<(Hash256, BeaconState<E>), Err>,
    {
        let mut inner = self.inner.lock();

        let suitable = match kind {
            AdvanceKind::Partial => inner.partial.as_ref(),
            AdvanceKind::Complete => inner.complete.as_ref(),
        }
        .filter(|entry| {
            entry.head_block_root == head_block_root && entry.state.slot() >= target_slot
        })
        .cloned();
        if let Some(entry) = suitable {
            return Ok(entry);
        }

        // Prefer extending the matching kind; a complete advance can also seed a partial request.
        let from_matching = match kind {
            AdvanceKind::Partial => inner.partial.as_ref(),
            AdvanceKind::Complete => inner.complete.as_ref(),
        }
        .filter(|entry| {
            entry.head_block_root == head_block_root && entry.state.slot() <= target_slot
        })
        .map(|entry| (entry.state_root, entry.state.clone()));

        let from_complete_for_partial = if kind == AdvanceKind::Partial && from_matching.is_none() {
            inner
                .complete
                .as_ref()
                .filter(|entry| {
                    entry.head_block_root == head_block_root && entry.state.slot() <= target_slot
                })
                .map(|entry| (entry.state_root, entry.state.clone()))
        } else {
            None
        };

        let (start_root, start_state) = if let Some(v) = from_matching.or(from_complete_for_partial)
        {
            v
        } else {
            load_starting_state()?
        };

        if start_state.slot() >= target_slot {
            let entry = AdvancedHeadStateEntry::new(head_block_root, start_root, start_state);
            match kind {
                AdvanceKind::Partial => Self::store(&mut inner.partial, entry.clone()),
                AdvanceKind::Complete => Self::store(&mut inner.complete, entry.clone()),
            }
            return Ok(entry);
        }

        debug!(
            ?kind,
            ?head_block_root,
            from_slot = %start_state.slot(),
            %target_slot,
            "Advancing retained head state"
        );

        let (state_root, state) = advance(start_state, start_root, target_slot)?;
        let entry = AdvancedHeadStateEntry::new(head_block_root, state_root, state);
        match kind {
            AdvanceKind::Partial => Self::store(&mut inner.partial, entry.clone()),
            AdvanceKind::Complete => Self::store(&mut inner.complete, entry.clone()),
        }
        Ok(entry)
    }

    /// Update the complete entry after the state-advance timer (proper per-slot roots).
    pub fn observe_complete_advanced_state(
        &self,
        head_block_root: Hash256,
        state_root: Hash256,
        state: &BeaconState<E>,
    ) {
        let entry = AdvancedHeadStateEntry::new(head_block_root, state_root, state.clone());
        let mut inner = self.inner.lock();
        Self::store(&mut inner.complete, entry);
    }
}
