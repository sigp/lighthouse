//! Retains one furthest empty-slot advance of the canonical head for reuse (#9530).
//!
//! Validator API handlers that need a state at the wall-clock epoch used to clone the
//! unadvanced head and `partial_state_advance` through every empty epoch. During a prolonged
//! outage that cost grows as O(staleness) on every new epoch (and every concurrent caller).
//!
//! This cache keeps a single advanced `BeaconState` for the current head block root and extends
//! it incrementally. Advances for the same head are serialized on a mutex so concurrent callers
//! share one catch-up (waiters then clone the retained state). Head changes discard the entry.
//!
//! Memory overhead is intentionally one extra in-memory state.

use parking_lot::Mutex;
use tracing::debug;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// Furthest empty-slot advance retained for the current head.
#[derive(Clone)]
pub struct AdvancedHeadStateEntry<E: EthSpec> {
    pub head_block_root: Hash256,
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

/// At most one retained advanced head state.
#[derive(Default)]
pub struct AdvancedHeadStateCache<E: EthSpec> {
    inner: Mutex<Option<AdvancedHeadStateEntry<E>>>,
}

impl<E: EthSpec> AdvancedHeadStateCache<E> {
    /// Discard the retained state when the head changes (or for tests).
    pub fn invalidate(&self) {
        *self.inner.lock() = None;
    }

    /// Replace the retained entry when `entry` is a further advance of the same head (or a new head).
    fn store(latest: &mut Option<AdvancedHeadStateEntry<E>>, entry: AdvancedHeadStateEntry<E>) {
        let replace = match latest.as_ref() {
            None => true,
            Some(existing) if existing.head_block_root != entry.head_block_root => true,
            Some(existing) => entry.state.slot() >= existing.state.slot(),
        };
        if replace {
            *latest = Some(entry);
        }
    }

    /// Return a state for `head_block_root` advanced to at least `target_slot`.
    ///
    /// - If the retained state already reaches `target_slot`, clone and return it.
    /// - Else start from the retained state (same head) or `load_starting_state`, run `advance`,
    ///   retain the result, and return it.
    ///
    /// The mutex is held for the duration of a miss (including `advance`) so concurrent callers
    /// coalesce onto a single catch-up. `advance` should persist the state (e.g. `store.put_state`)
    /// so other paths such as `get_advanced_hot_state` can reuse it.
    pub fn get_or_advance_to<Err, Load, Advance>(
        &self,
        head_block_root: Hash256,
        target_slot: Slot,
        load_starting_state: Load,
        advance: Advance,
    ) -> Result<AdvancedHeadStateEntry<E>, Err>
    where
        Load: FnOnce() -> Result<(Hash256, BeaconState<E>), Err>,
        Advance: FnOnce(BeaconState<E>, Hash256, Slot) -> Result<(Hash256, BeaconState<E>), Err>,
    {
        let mut latest = self.inner.lock();

        if let Some(entry) = latest.as_ref()
            && entry.head_block_root == head_block_root
            && entry.state.slot() >= target_slot
        {
            return Ok(entry.clone());
        }

        let (start_root, start_state) = if let Some(entry) = latest.as_ref()
            && entry.head_block_root == head_block_root
            && entry.state.slot() <= target_slot
        {
            (entry.state_root, entry.state.clone())
        } else {
            load_starting_state()?
        };

        if start_state.slot() >= target_slot {
            let entry = AdvancedHeadStateEntry::new(head_block_root, start_root, start_state);
            Self::store(&mut latest, entry.clone());
            return Ok(entry);
        }

        debug!(
            ?head_block_root,
            from_slot = %start_state.slot(),
            %target_slot,
            "Advancing retained head state"
        );

        let (state_root, state) = advance(start_state, start_root, target_slot)?;
        let entry = AdvancedHeadStateEntry::new(head_block_root, state_root, state);
        Self::store(&mut latest, entry.clone());
        Ok(entry)
    }

    /// Update the cache after the state-advance timer (or similar) has already advanced a state.
    pub fn observe_advanced_state(
        &self,
        head_block_root: Hash256,
        state_root: Hash256,
        state: &BeaconState<E>,
    ) {
        let entry = AdvancedHeadStateEntry::new(head_block_root, state_root, state.clone());
        let mut latest = self.inner.lock();
        Self::store(&mut latest, entry);
    }
}
