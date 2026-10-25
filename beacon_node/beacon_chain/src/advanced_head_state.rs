//! Retains empty-slot advances of the canonical head so validator API calls stay cheap while
//! the chain is not producing blocks.
//!
//! Validator API handlers that need a state at the wall-clock epoch used to clone the
//! unadvanced head and replay every empty epoch. During an outage that cost grows with
//! staleness, and it was paid again on every new epoch and by every concurrent caller.
//!
//! The cache keeps at most:
//! - one partial advance (intermediate state roots are not computed; suitable for shuffling,
//!   duties, and attestation justified checkpoints), and
//! - one complete advance (valid state roots; suitable for block production).
//!
//! Callers always receive a state at exactly the slot they asked for. An entry is reused only
//! when its slot is less than or equal to the target; it is then cloned and advanced forward.
//! Anything past roughly the wall clock plus one epoch is computed on a throwaway clone and is
//! not stored, so a far request cannot evict the entry later callers need.
//!
//! ## Single-flight and invalidation
//!
//! Advances for the same head, kind, and target share one in-flight computation. The computation
//! runs outside the cache mutex. `invalidate` does not wait for it: it bumps a generation and
//! drops the entries. A store from an older generation is ignored, so a head change cannot be
//! blocked by a long advance and cannot be overwritten by that advance finishing late.
//!
//! ## Lock ordering
//!
//! `canonical_head`'s `recompute_head` mutex is taken before this cache mutex (`invalidate` runs
//! while `recompute_head` is held). This mutex is taken before the store `state_cache` mutex and
//! the hot/cold split read lock, but those store locks are acquired only on the load path, which
//! runs outside this mutex. Do not advance a state or read the database while holding this mutex.
//!
//! ## What is safe to persist
//!
//! Partial results must not be written with `put_state`. Complete results have valid state roots
//! and may be used for block production, but this cache does not persist them. A multi-slot jump
//! does not form the continuous hot-summary chain `put_state` expects. The state-advance timer
//! persists at most one slot at a time, and only within `MAX_ADVANCE_DISTANCE` of the head block.
//!
//! Importing a block this node produced still replays empty slots once. The demand-path complete
//! state lives only in this cache, so block import loads the unadvanced head from the store.
//! That replay is paid once per new head; the new head snapshot then replaces these entries.

use crate::metrics;
use oneshot_broadcast::{Receiver, oneshot};
use parking_lot::{Mutex, MutexGuard};
use std::collections::HashMap;
use tracing::debug;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// One retained empty-slot advance of a single head block.
#[derive(Clone)]
pub(crate) struct AdvancedHeadStateEntry<E: EthSpec> {
    pub(crate) head_block_root: Hash256,
    /// State root to feed the next partial or complete advance.
    ///
    /// For a partial advance this is zero once the state is past the block header slot.
    pub(crate) state_root: Hash256,
    pub(crate) state: BeaconState<E>,
}

impl<E: EthSpec> AdvancedHeadStateEntry<E> {
    pub(crate) fn new(
        head_block_root: Hash256,
        state_root: Hash256,
        state: BeaconState<E>,
    ) -> Self {
        Self {
            head_block_root,
            state_root,
            state,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AdvanceKind {
    /// Skip intermediate state roots. The state is not consensus-valid.
    Partial,
    /// Compute proper state roots. The state may be used for block production.
    Complete,
}

/// Parameters for one `get_or_advance_to` call.
pub(crate) struct AdvanceRequest {
    pub(crate) kind: AdvanceKind,
    pub(crate) head_block_root: Hash256,
    pub(crate) target_slot: Slot,
    /// Furthest slot this call is allowed to retain. Typically the wall-clock slot plus one epoch.
    pub(crate) max_store_slot: Slot,
    pub(crate) wall_clock_slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlightKey {
    generation: u64,
    head_block_root: Hash256,
    kind: AdvanceKind,
    target_slot: Slot,
}

struct Inner<E: EthSpec> {
    generation: u64,
    partial: Option<AdvancedHeadStateEntry<E>>,
    complete: Option<AdvancedHeadStateEntry<E>>,
    flights: HashMap<FlightKey, Receiver<Option<AdvancedHeadStateEntry<E>>>>,
}

impl<E: EthSpec> Default for Inner<E> {
    fn default() -> Self {
        Self {
            generation: 0,
            partial: None,
            complete: None,
            flights: HashMap::new(),
        }
    }
}

/// At most one partial and one complete retained advanced head state.
#[derive(Default)]
pub struct AdvancedHeadStateCache<E: EthSpec> {
    inner: Mutex<Inner<E>>,
}

impl<E: EthSpec> AdvancedHeadStateCache<E> {
    fn lock(&self) -> MutexGuard<'_, Inner<E>> {
        let _timer = metrics::start_timer(&metrics::ADVANCED_HEAD_STATE_LOCK_WAIT);
        self.inner.lock()
    }

    /// Drop retained states and abandon in-flight stores.
    ///
    /// Does not wait for an advance that is already running. That advance may still finish and
    /// return a state to the caller that started it, but the result is not stored.
    pub fn invalidate(&self) {
        let mut inner = self.lock();
        inner.generation = inner.generation.wrapping_add(1);
        inner.partial = None;
        inner.complete = None;
        // Receivers already handed out still resolve. New callers miss this map and start fresh.
        inner.flights.clear();
        publish_gauges(&inner, None);
    }

    /// Generation observed by `invalidate`. A store must present the same value to be kept.
    pub(crate) fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Clone of the complete entry for `head_block_root` whose slot is `<= max_slot`, if any.
    pub(crate) fn complete_seed(
        &self,
        head_block_root: Hash256,
        max_slot: Slot,
    ) -> Option<AdvancedHeadStateEntry<E>> {
        let inner = self.lock();
        inner.complete.as_ref().and_then(|entry| {
            if entry.head_block_root == head_block_root && entry.state.slot() <= max_slot {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    /// Update gauges from the current entries. `wall_clock_slot` sets the lag gauges.
    pub(crate) fn scrape_metrics(&self, wall_clock_slot: Option<Slot>) {
        let inner = self.lock();
        publish_gauges(&inner, wall_clock_slot);
    }

    /// Return a state for `head_block_root` advanced to exactly `request.target_slot`.
    ///
    /// `load_starting_state` must return a state at slot `<= target_slot`. It runs outside the
    /// cache mutex. `advance` must move the state forward to the slot it is given and also runs
    /// outside the mutex.
    ///
    /// On a hit the returned state's slot is `target_slot`. The cache may retain a different slot:
    /// the furthest retained slot is `min(target_slot, max_store_slot)`.
    pub(crate) fn get_or_advance_to<Err, Load, Advance>(
        &self,
        request: AdvanceRequest,
        mut load_starting_state: Load,
        mut advance: Advance,
    ) -> Result<AdvancedHeadStateEntry<E>, Err>
    where
        Load: FnMut() -> Result<(Hash256, BeaconState<E>), Err>,
        Advance: FnMut(BeaconState<E>, Hash256, Slot) -> Result<(Hash256, BeaconState<E>), Err>,
    {
        // A failed leader asks waiters to retry. Cap the retries, then compute directly.
        const MAX_JOINS: usize = 3;
        for join in 0..MAX_JOINS {
            let mut inner = self.lock();
            let generation = inner.generation;

            if let Some(hit) = exact_hit(
                &inner,
                request.kind,
                request.head_block_root,
                request.target_slot,
            ) {
                let entry = hit.clone();
                publish_gauges(&inner, Some(request.wall_clock_slot));
                drop(inner);
                metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_HITS);
                return Ok(entry);
            }

            let flight_key = FlightKey {
                generation,
                head_block_root: request.head_block_root,
                kind: request.kind,
                target_slot: request.target_slot,
            };
            if join + 1 < MAX_JOINS
                && let Some(receiver) = inner.flights.get(&flight_key).cloned()
            {
                drop(inner);
                metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_COALESCED);
                match receiver.recv() {
                    Ok(Some(entry)) => return Ok(entry),
                    Ok(None) | Err(_) => continue,
                }
            }

            let (sender, receiver) = oneshot();
            inner.flights.insert(flight_key, receiver);
            let seed = select_seed(
                &inner,
                request.kind,
                request.head_block_root,
                request.target_slot,
            )
            .cloned();
            drop(inner);

            metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_MISSES);
            let result = self.run_advance(
                &request,
                generation,
                seed,
                &mut load_starting_state,
                &mut advance,
            );
            {
                let mut inner = self.lock();
                inner.flights.remove(&flight_key);
                publish_gauges(&inner, Some(request.wall_clock_slot));
            }
            sender.send(result.as_ref().ok().cloned());
            return result;
        }

        // Unreachable: the last attempt does not join and always returns.
        unreachable!("advanced head state flight retry exceeded its cap without leading");
    }

    fn run_advance<Err, Load, Advance>(
        &self,
        request: &AdvanceRequest,
        generation: u64,
        seed: Option<AdvancedHeadStateEntry<E>>,
        load_starting_state: &mut Load,
        advance: &mut Advance,
    ) -> Result<AdvancedHeadStateEntry<E>, Err>
    where
        Load: FnMut() -> Result<(Hash256, BeaconState<E>), Err>,
        Advance: FnMut(BeaconState<E>, Hash256, Slot) -> Result<(Hash256, BeaconState<E>), Err>,
    {
        let (mut state_root, mut state) = if let Some(seed) = seed {
            (seed.state_root, seed.state)
        } else {
            load_starting_state()?
        };

        // Never hand back a later slot. `advance` is required to reject `state.slot() > target`.
        if state.slot() > request.target_slot {
            let (root, state) = advance(state, state_root, request.target_slot)?;
            return Ok(AdvancedHeadStateEntry::new(
                request.head_block_root,
                root,
                state,
            ));
        }

        let store_ceiling = std::cmp::min(request.target_slot, request.max_store_slot);

        if state.slot() < store_ceiling {
            let before = state.slot();
            let (root, advanced) = advance(state, state_root, store_ceiling)?;
            record_slots_advanced(before, advanced.slot());
            state_root = root;
            state = advanced;
            self.try_store(
                generation,
                request.kind,
                AdvancedHeadStateEntry::new(request.head_block_root, state_root, state.clone()),
                request.max_store_slot,
            );
        } else if state.slot() == store_ceiling {
            // Already at the furthest slot we are allowed to retain (a disk load, or a seed).
            self.try_store(
                generation,
                request.kind,
                AdvancedHeadStateEntry::new(request.head_block_root, state_root, state.clone()),
                request.max_store_slot,
            );
        }

        if state.slot() < request.target_slot {
            let before = state.slot();
            let (root, advanced) = advance(state, state_root, request.target_slot)?;
            record_slots_advanced(before, advanced.slot());
            // Past the retain window: the caller gets the state, the cache does not keep it.
            debug!(
                kind = ?request.kind,
                head_block_root = ?request.head_block_root,
                target_slot = %request.target_slot,
                max_store_slot = %request.max_store_slot,
                "Computed advanced head state past the retain window"
            );
            state_root = root;
            state = advanced;
        }

        Ok(AdvancedHeadStateEntry::new(
            request.head_block_root,
            state_root,
            state,
        ))
    }

    fn try_store(
        &self,
        generation: u64,
        kind: AdvanceKind,
        entry: AdvancedHeadStateEntry<E>,
        max_store_slot: Slot,
    ) {
        if entry.state.slot() > max_store_slot {
            return;
        }
        if !block_root_matches(&entry) {
            metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_BLOCK_ROOT_MISMATCH);
            debug!(
                ?kind,
                head_block_root = ?entry.head_block_root,
                state_slot = %entry.state.slot(),
                "Refusing to retain advanced head state for a different block"
            );
            return;
        }

        let mut inner = self.lock();
        if inner.generation != generation {
            metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_STALE_STORE);
            debug!(
                ?kind,
                head_block_root = ?entry.head_block_root,
                state_slot = %entry.state.slot(),
                "Dropping advanced head state from a stale generation"
            );
            return;
        }
        let slot = match kind {
            AdvanceKind::Partial => &mut inner.partial,
            AdvanceKind::Complete => &mut inner.complete,
        };
        store(slot, entry);
    }

    /// Update the complete entry after the state-advance timer (proper per-slot roots).
    ///
    /// `generation` must be the value observed before the advance started. A head change in
    /// between bumps the generation and this store is ignored.
    pub(crate) fn observe_complete_advanced_state(
        &self,
        generation: u64,
        head_block_root: Hash256,
        state_root: Hash256,
        state: &BeaconState<E>,
    ) {
        let entry = AdvancedHeadStateEntry::new(head_block_root, state_root, state.clone());
        if !block_root_matches(&entry) {
            metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_BLOCK_ROOT_MISMATCH);
            return;
        }
        let mut inner = self.lock();
        if inner.generation != generation {
            metrics::inc_counter(&metrics::ADVANCED_HEAD_STATE_STALE_STORE);
            return;
        }
        store(&mut inner.complete, entry);
    }
}

fn store<E: EthSpec>(
    slot: &mut Option<AdvancedHeadStateEntry<E>>,
    entry: AdvancedHeadStateEntry<E>,
) {
    let replace = match slot.as_ref() {
        None => true,
        Some(existing) if existing.head_block_root != entry.head_block_root => true,
        Some(existing) => entry.state.slot() >= existing.state.slot(),
    };
    if replace {
        *slot = Some(entry);
    }
}

fn selectable<E: EthSpec>(
    entry: &AdvancedHeadStateEntry<E>,
    head_block_root: Hash256,
    target_slot: Slot,
) -> bool {
    entry.head_block_root == head_block_root && entry.state.slot() <= target_slot
}

/// Furthest entry at or before `target_slot`.
///
/// A partial request may start from either kind. A complete request starts only from the complete
/// entry: a partial state must not seed block production.
fn select_seed<E: EthSpec>(
    inner: &Inner<E>,
    kind: AdvanceKind,
    head_block_root: Hash256,
    target_slot: Slot,
) -> Option<&AdvancedHeadStateEntry<E>> {
    let partial = inner
        .partial
        .as_ref()
        .filter(|entry| selectable(entry, head_block_root, target_slot));
    let complete = inner
        .complete
        .as_ref()
        .filter(|entry| selectable(entry, head_block_root, target_slot));
    match kind {
        AdvanceKind::Partial => match (partial, complete) {
            (Some(partial), Some(complete)) => {
                Some(if partial.state.slot() >= complete.state.slot() {
                    partial
                } else {
                    complete
                })
            }
            (Some(partial), None) => Some(partial),
            (None, Some(complete)) => Some(complete),
            (None, None) => None,
        },
        AdvanceKind::Complete => complete,
    }
}

fn exact_hit<E: EthSpec>(
    inner: &Inner<E>,
    kind: AdvanceKind,
    head_block_root: Hash256,
    target_slot: Slot,
) -> Option<&AdvancedHeadStateEntry<E>> {
    let matches = |entry: &AdvancedHeadStateEntry<E>| {
        entry.head_block_root == head_block_root && entry.state.slot() == target_slot
    };
    let partial = inner.partial.as_ref().filter(|entry| matches(entry));
    let complete = inner.complete.as_ref().filter(|entry| matches(entry));
    match kind {
        // Prefer the complete state when both sit on the target: its state root is real.
        AdvanceKind::Partial => complete.or(partial),
        AdvanceKind::Complete => complete,
    }
}

/// `get_latest_block_root` fills a zero `latest_block_header.state_root` before hashing.
///
/// Comparing `latest_block_header().canonical_root()` directly rejects the head state on its own
/// slot, where that field is still zero. After at least one slot of advance the header root is
/// the block root either way.
fn block_root_matches<E: EthSpec>(entry: &AdvancedHeadStateEntry<E>) -> bool {
    entry.state.get_latest_block_root(entry.state_root) == entry.head_block_root
}

fn record_slots_advanced(before: Slot, after: Slot) {
    let slots = after.as_u64().saturating_sub(before.as_u64());
    if slots > 0 {
        metrics::inc_counter_by(&metrics::ADVANCED_HEAD_STATE_SLOTS_ADVANCED, slots);
    }
}

fn publish_gauges<E: EthSpec>(inner: &Inner<E>, wall_clock_slot: Option<Slot>) {
    let wall = wall_clock_slot.map(|slot| slot.as_u64() as i64);
    publish_one(
        inner.partial.as_ref().map(|entry| entry.state.slot()),
        wall,
        &metrics::ADVANCED_HEAD_STATE_PARTIAL_SLOT,
        &metrics::ADVANCED_HEAD_STATE_PARTIAL_SLOT_LAG,
    );
    publish_one(
        inner.complete.as_ref().map(|entry| entry.state.slot()),
        wall,
        &metrics::ADVANCED_HEAD_STATE_COMPLETE_SLOT,
        &metrics::ADVANCED_HEAD_STATE_COMPLETE_SLOT_LAG,
    );
}

fn publish_one(
    slot: Option<Slot>,
    wall: Option<i64>,
    slot_gauge: &metrics::Result<metrics::IntGauge>,
    lag_gauge: &metrics::Result<metrics::IntGauge>,
) {
    match slot {
        Some(slot) => {
            let slot = slot.as_u64() as i64;
            metrics::set_gauge(slot_gauge, slot);
            if let Some(wall) = wall {
                metrics::set_gauge(lag_gauge, wall - slot);
            }
        }
        None => {
            metrics::set_gauge(slot_gauge, 0);
            if wall.is_some() {
                metrics::set_gauge(lag_gauge, 0);
            }
        }
    }
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::BeaconChainError;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use state_processing::state_advance::{complete_state_advance, partial_state_advance};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use types::{ChainSpec, EthSpec, Hash256, Slot};

    type E = types::Spec;

    struct Fixture {
        harness: BeaconChainHarness<EphemeralHarnessType<E>>,
        block_root: Hash256,
        state_root: Hash256,
        base_slot: Slot,
    }

    fn fixture() -> Fixture {
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .deterministic_keypairs(E::slots_per_epoch() as usize)
            .fresh_ephemeral_store()
            .build();
        let head = harness.chain.canonical_head.cached_head();
        let block_root = head.head_block_root();
        let state_root = head.head_state_root();
        let base_slot = head.head_slot();
        Fixture {
            harness,
            block_root,
            state_root,
            base_slot,
        }
    }

    fn spec(fixture: &Fixture) -> Arc<ChainSpec> {
        fixture.harness.chain.spec.clone()
    }

    fn base_state(fixture: &Fixture) -> BeaconState<E> {
        fixture
            .harness
            .chain
            .canonical_head
            .cached_head()
            .snapshot
            .beacon_state
            .clone()
    }

    fn request(
        fixture: &Fixture,
        kind: AdvanceKind,
        target: Slot,
        max_store: Slot,
    ) -> AdvanceRequest {
        AdvanceRequest {
            kind,
            head_block_root: fixture.block_root,
            target_slot: target,
            max_store_slot: max_store,
            wall_clock_slot: max_store,
        }
    }

    fn advance_partial(
        spec: &ChainSpec,
    ) -> impl FnMut(
        BeaconState<E>,
        Hash256,
        Slot,
    ) -> Result<(Hash256, BeaconState<E>), BeaconChainError>
    + '_ {
        |mut state, state_root, target| {
            partial_state_advance(&mut state, Some(state_root), target, None, spec)?;
            Ok((Hash256::ZERO, state))
        }
    }

    fn advance_complete(
        spec: &ChainSpec,
    ) -> impl FnMut(
        BeaconState<E>,
        Hash256,
        Slot,
    ) -> Result<(Hash256, BeaconState<E>), BeaconChainError>
    + '_ {
        |mut state, state_root, target| {
            complete_state_advance(&mut state, Some(state_root), target, None, spec)?;
            let root = state.update_tree_hash_cache()?;
            Ok((root, state))
        }
    }

    fn stored_slots<E: EthSpec>(cache: &AdvancedHeadStateCache<E>) -> (Option<Slot>, Option<Slot>) {
        let inner = cache.inner.lock();
        (
            inner.partial.as_ref().map(|entry| entry.state.slot()),
            inner.complete.as_ref().map(|entry| entry.state.slot()),
        )
    }

    #[test]
    fn returns_the_exact_target_and_keeps_a_later_entry() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let later = fixture.base_slot + 4;
        let earlier = fixture.base_slot + 2;
        let state = base_state(&fixture);

        let got = cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, later, later),
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();
        assert_eq!(got.state.slot(), later);

        let mut loads = 0;
        let got = cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, earlier, later),
                || {
                    loads += 1;
                    Ok((fixture.state_root, state.clone()))
                },
                advance_partial(&spec),
            )
            .unwrap();
        assert_eq!(got.state.slot(), earlier);
        assert_eq!(loads, 1, "a later entry must not seed an earlier target");
        assert_eq!(stored_slots(&cache).0, Some(later));
    }

    #[test]
    fn partial_request_seeds_from_the_furthest_entry_of_either_kind() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let state = base_state(&fixture);
        let partial_slot = fixture.base_slot + 2;
        let complete_slot = fixture.base_slot + 5;
        let target = fixture.base_slot + 8;

        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, partial_slot, target),
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();
        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Complete, complete_slot, target),
                || Ok((fixture.state_root, state.clone())),
                advance_complete(&spec),
            )
            .unwrap();

        let mut started_at = None;
        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, target, target),
                || Ok((fixture.state_root, state.clone())),
                |state, root, target| {
                    started_at = Some(state.slot());
                    advance_partial(&spec)(state, root, target)
                },
            )
            .unwrap();
        assert_eq!(started_at, Some(complete_slot));
    }

    #[test]
    fn complete_request_does_not_seed_from_a_partial_entry() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let state = base_state(&fixture);
        let partial_slot = fixture.base_slot + 5;
        let target = fixture.base_slot + 8;

        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, partial_slot, target),
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();

        let mut started_at = None;
        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Complete, target, target),
                || Ok((fixture.state_root, state.clone())),
                |state, root, target| {
                    started_at = Some(state.slot());
                    advance_complete(&spec)(state, root, target)
                },
            )
            .unwrap();
        assert_eq!(started_at, Some(fixture.base_slot));
        assert!(stored_slots(&cache).1.unwrap() <= target);
    }

    #[test]
    fn targets_past_the_retain_window_are_not_stored() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let state = base_state(&fixture);
        let ceiling = fixture.base_slot + 2;
        let target = fixture.base_slot + 6;

        let got = cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, target, ceiling),
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();
        assert_eq!(got.state.slot(), target);
        assert_eq!(stored_slots(&cache).0, Some(ceiling));
    }

    #[test]
    fn repeated_exact_target_does_not_advance_again() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let state = base_state(&fixture);
        let target = fixture.base_slot + 3;
        cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, target, target),
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();

        let mut advances = 0;
        let got = cache
            .get_or_advance_to(
                request(&fixture, AdvanceKind::Partial, target, target),
                || Ok((fixture.state_root, state.clone())),
                |state, root, target| {
                    advances += 1;
                    advance_partial(&spec)(state, root, target)
                },
            )
            .unwrap();
        assert_eq!(got.state.slot(), target);
        assert_eq!(advances, 0);
    }

    #[test]
    fn mismatched_block_root_is_not_retained() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = AdvancedHeadStateCache::<E>::default();
        let state = base_state(&fixture);
        let target = fixture.base_slot + 1;
        let mut wrong = request(&fixture, AdvanceKind::Partial, target, target);
        wrong.head_block_root = Hash256::from_slice(&[0x11; 32]);

        let got = cache
            .get_or_advance_to(
                wrong,
                || Ok((fixture.state_root, state.clone())),
                advance_partial(&spec),
            )
            .unwrap();
        assert_eq!(got.state.slot(), target);
        assert_eq!(stored_slots(&cache), (None, None));
    }

    #[test]
    fn invalidate_does_not_wait_and_rejects_the_in_flight_store() {
        let fixture = fixture();
        let spec = spec(&fixture);
        let cache = Arc::new(AdvancedHeadStateCache::<E>::default());
        let state = base_state(&fixture);
        let target = fixture.base_slot + 4;
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));

        let cache_worker = cache.clone();
        let started_worker = started.clone();
        let release_worker = release.clone();
        let block_root = fixture.block_root;
        let state_root = fixture.state_root;
        let worker = thread::spawn(move || {
            cache_worker.get_or_advance_to(
                AdvanceRequest {
                    kind: AdvanceKind::Complete,
                    head_block_root: block_root,
                    target_slot: target,
                    max_store_slot: target,
                    wall_clock_slot: target,
                },
                || Ok::<_, BeaconChainError>((state_root, state.clone())),
                |state, root, target| {
                    started_worker.wait();
                    release_worker.wait();
                    advance_complete(&spec)(state, root, target)
                },
            )
        });

        started.wait();
        let (invalidate_done_tx, invalidate_done_rx) = std::sync::mpsc::channel();
        let cache_invalidate = cache.clone();
        thread::spawn(move || {
            cache_invalidate.invalidate();
            let _ = invalidate_done_tx.send(());
        });
        assert!(
            invalidate_done_rx
                .recv_timeout(Duration::from_secs(2))
                .is_ok(),
            "invalidate blocked on the in-flight advance"
        );
        release.wait();
        worker.join().unwrap().unwrap();
        assert_eq!(
            stored_slots(&cache),
            (None, None),
            "a store that races invalidate must be dropped"
        );
    }
}
