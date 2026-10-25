//! Provides a timer which runs in the tail-end of each slot and maybe advances the state of the
//! head block forward a single slot.
//!
//! This provides an optimization with the following benefits:
//!
//! 1. Removes the burden of a single, mandatory `per_slot_processing` call from the leading-edge of
//!    block processing. This helps import blocks faster.
//! 2. Allows the node to learn of the shuffling for the next epoch, before the first block from
//!    that epoch has arrived. This helps reduce gossip block propagation times.
//!
//! The downsides to this optimization are:
//!
//! 1. We are required to store an additional `BeaconState` for the head block. This consumes
//!    memory.
//! 2. There's a possibility that the head block is never built upon, causing wasted CPU cycles.
use crate::metrics;
use crate::validator_monitor::HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS;
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes,
    chain_config::FORK_CHOICE_LOOKAHEAD_FACTOR,
    shuffling_cache::{CachedPTCs, CachedShuffling},
};
use slot_clock::SlotClock;
use state_processing::{
    GloasVerificationContext, per_slot_processing, state_advance::complete_state_advance,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use task_executor::TaskExecutor;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::{Instrument, debug, debug_span, error, instrument, warn};
use types::{AttestationShufflingId, BeaconStateError, EthSpec, Hash256, RelativeEpoch, Slot};

/// If the head slot is more than `MAX_ADVANCE_DISTANCE` from the current slot and the node is
/// long-range syncing, then don't perform the state advancement.
///
/// Whilst syncing, a far-behind head is about to be replaced by imported blocks, so advancing it
/// wastes CPU. When the node is synced or stalled (no peers, clock running, no new blocks), the
/// timer still catches the in-memory advanced-head entry up to the wall clock. Hot-database
/// writes stay inside this distance: past it, only the in-memory entry moves.
pub(crate) const MAX_ADVANCE_DISTANCE: u64 = 256;

/// Similarly for fork choice: avoid the fork choice lookahead during sync.
///
/// The value is set to 256 since this would be just over one slot (12.8s) when syncing at
/// 20 slots/second. Having a single fork-choice run interrupt syncing would have very little
/// impact whilst having 8 epochs without a block is a comfortable grace period.
const MAX_FORK_CHOICE_DISTANCE: u64 = 256;

#[derive(Debug)]
enum Error {
    BeaconChain(Box<BeaconChainError>),
    // We don't use the inner value directly, but it's used in the Debug impl.
    HeadMissingFromSnapshotCache(#[allow(dead_code)] Hash256),
    BeaconState(#[allow(dead_code)] BeaconStateError),
    Store(#[allow(dead_code)] store::Error),
    MaxDistanceExceeded { current_slot: Slot, head_slot: Slot },
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Self::BeaconChain(e.into())
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Store(e)
    }
}

/// Provides a simple thread-safe lock to be used for task co-ordination. Practically equivalent to
/// `Mutex<()>`.
#[derive(Clone)]
struct Lock(Arc<AtomicBool>);

impl Lock {
    /// Instantiate an unlocked self.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Lock self, returning `true` if the lock was already set.
    pub fn lock(&self) -> bool {
        self.0.fetch_or(true, Ordering::SeqCst)
    }

    /// Unlock self.
    pub fn unlock(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Spawns the timer described in the module-level documentation.
///
/// `is_long_range_syncing` should return `true` while the node is performing range sync
/// (`SyncingFinalized` / `SyncingHead` / `SyncTransition`), and when the caller has no view of
/// sync status. When `true`, advancement stops once the head lags by more than
/// [`MAX_ADVANCE_DISTANCE`]. When `false` (synced or stalled), the in-memory entry still catches
/// up past that distance, but hot-database writes do not.
pub fn spawn_state_advance_timer<T, F>(
    executor: TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    is_long_range_syncing: F,
) where
    T: BeaconChainTypes,
    F: Fn() -> bool + Send + Sync + 'static,
{
    executor.spawn(
        state_advance_timer(executor.clone(), beacon_chain, is_long_range_syncing),
        "state_advance_timer",
    );
}

/// Provides the timer described in the module-level documentation.
async fn state_advance_timer<T, F>(
    executor: TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    is_long_range_syncing: F,
) where
    T: BeaconChainTypes,
    F: Fn() -> bool + Send + Sync + 'static,
{
    let is_running = Lock::new();
    let slot_clock = &beacon_chain.slot_clock;
    let slot_duration = slot_clock.slot_duration();

    loop {
        let Some(duration_to_next_slot) = beacon_chain.slot_clock.duration_to_next_slot() else {
            error!("Failed to read slot clock");
            // If we can't read the slot clock, just wait another slot.
            sleep(slot_duration).await;
            continue;
        };

        // Run the state advance 3/4 of the way through the slot (9s on mainnet).
        let state_advance_offset = slot_duration / 4;
        let state_advance_instant = if duration_to_next_slot > state_advance_offset {
            Instant::now() + duration_to_next_slot - state_advance_offset
        } else {
            // Skip the state advance for the current slot and wait until the next one.
            Instant::now() + duration_to_next_slot + slot_duration - state_advance_offset
        };

        // Run fork choice 23/24s of the way through the slot (11.5s on mainnet).
        // We need to run after the state advance, so use the same condition as above.
        let fork_choice_offset = slot_duration / FORK_CHOICE_LOOKAHEAD_FACTOR;
        let fork_choice_instant = if duration_to_next_slot > state_advance_offset {
            Instant::now() + duration_to_next_slot - fork_choice_offset
        } else {
            Instant::now() + duration_to_next_slot + slot_duration - fork_choice_offset
        };

        // Wait for the state advance.
        sleep_until(state_advance_instant).await;

        // Compute the current slot here at approx 3/4 through the slot. Even though this slot is
        // only used by fork choice we need to calculate it here rather than after the state
        // advance, in case the state advance flows over into the next slot.
        let current_slot = match beacon_chain.slot() {
            Ok(slot) => slot,
            Err(e) => {
                warn!(
                    error = ?e,
                    "Unable to determine slot in state advance timer"
                );
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
                continue;
            }
        };

        // Only spawn the state advance task if the lock was previously free.
        if !is_running.lock() {
            let beacon_chain = beacon_chain.clone();
            let is_running = is_running.clone();
            let refuse_far_advance = is_long_range_syncing();

            executor.spawn_blocking(
                move || {
                    match advance_head(&beacon_chain, refuse_far_advance) {
                        Ok(()) => (),
                        Err(Error::BeaconChain(e)) => error!(
                            error = ?e,
                            "Failed to advance head state"
                        ),
                        Err(Error::MaxDistanceExceeded {
                            current_slot,
                            head_slot,
                        }) => debug!(%head_slot, %current_slot, "Refused to advance head state"),
                        other => warn!(
                            reason = ?other,
                            "Did not advance head state"
                        ),
                    };

                    // Permit this blocking task to spawn again, next time the timer fires.
                    is_running.unlock();
                },
                "state_advance_blocking",
            );
        } else {
            warn!(
                msg = "system resources may be overloaded",
                "State advance routine overloaded"
            )
        }

        // Run fork choice pre-emptively for the next slot. This processes most of the attestations
        // from this slot off the hot path of block verification and production.
        // Wait for the fork choice instant (which may already be past).
        sleep_until(fork_choice_instant).await;

        let beacon_chain = beacon_chain.clone();
        let next_slot = current_slot + 1;
        executor.spawn(
            async move {
                // Don't run fork choice during sync.
                if beacon_chain.best_slot() + MAX_FORK_CHOICE_DISTANCE < current_slot {
                    return;
                }

                // Re-compute the head, dequeuing attestations for the current slot early.
                beacon_chain.recompute_head_at_slot(next_slot).await;

                // Prepare proposers so that the node can send payload attributes in the case where
                // it decides to abandon a proposer boost re-org.
                beacon_chain
                    .prepare_beacon_proposer(current_slot)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(
                            error = ?e,
                            slot = %next_slot,
                            "Unable to prepare proposer with lookahead"
                        );
                        None
                    });

                // Use a blocking task to avoid blocking the core executor whilst waiting for locks
                // in `ForkChoiceSignalTx`.
                beacon_chain.task_executor.clone().spawn_blocking(
                    move || {
                        // Signal block proposal for the next slot (if it happens to be waiting).
                        if let Some(tx) = &beacon_chain.fork_choice_signal_tx
                            && let Err(e) = tx.notify_fork_choice_complete(next_slot)
                        {
                            warn!(
                                error = ?e,
                                slot = %next_slot,
                                "Error signalling fork choice waiter"
                            );
                        }
                    },
                    "fork_choice_advance_signal_tx",
                );
            }
            .instrument(debug_span!("fork_choice_advance")),
            "fork_choice_advance",
        );
    }
}

/// Advance the canonical head toward the next slot.
///
/// When `refuse_far_advance` is true (long-range syncing, or no sync view), refuse to advance
/// if the head is more than [`MAX_ADVANCE_DISTANCE`] behind the wall clock.
///
/// Otherwise the in-memory complete entry is brought up to `current_slot + 1` in this call, so a
/// restart or a missed tick does not leave the timer one slot behind forever. Hot-database writes
/// stay inside [`MAX_ADVANCE_DISTANCE`] of the head block and only cover single-slot steps that
/// continue a state loaded from the store. Past that cap the timer drives only the in-memory
/// entry, seeded from the cache's complete entry when that entry is already ahead of the store.
#[instrument(skip_all)]
fn advance_head<T: BeaconChainTypes>(
    beacon_chain: &Arc<BeaconChain<T>>,
    refuse_far_advance: bool,
) -> Result<(), Error> {
    let current_slot = beacon_chain.slot()?;
    let head_slot = beacon_chain.best_slot();

    // Long-range sync (and a missing sync view) keeps the historical cap: a far-behind head is
    // about to be replaced, so do not spend the CPU.
    if refuse_far_advance && head_slot + MAX_ADVANCE_DISTANCE < current_slot {
        return Err(Error::MaxDistanceExceeded {
            current_slot,
            head_slot,
        });
    }

    // The timer runs three quarters of the way through `current_slot` and leaves the state one
    // slot ahead, which is `current_slot + 1` here. Block production for `current_slot` does not
    // use that later state; it advances an earlier entry to exactly the produce slot.
    let timer_target = current_slot + 1;
    let persist_limit = head_slot + MAX_ADVANCE_DISTANCE;

    let (head_block_root, head_block_state_root) = {
        let snapshot = beacon_chain.head_snapshot();
        (snapshot.beacon_block_root, snapshot.beacon_state_root())
    };

    // Captured before the work so a head change during the advance rejects the store.
    let generation = beacon_chain.advanced_head_state.generation();

    let memory = beacon_chain
        .advanced_head_state
        .complete_seed(head_block_root, timer_target);
    // Once the in-memory entry is past the persistence cap, do not reload the unadvanced head
    // from disk. That reload is what made a cache eviction restart the advance from the head.
    let memory_past_cap = memory
        .as_ref()
        .is_some_and(|entry| entry.state.slot() > persist_limit);
    let from_store = if memory_past_cap {
        None
    } else {
        beacon_chain.store.get_advanced_hot_state(
            head_block_root,
            std::cmp::min(timer_target, persist_limit),
            head_block_state_root,
        )?
    };

    let (mut state_root, mut state, persistable) = match (memory, from_store) {
        (Some(memory), Some((_store_root, store_state)))
            if memory.state.slot() > store_state.slot() =>
        {
            // The cache is ahead of anything the store can return. Extending it is in-memory
            // only: the jump that got it here was not written to disk.
            (memory.state_root, memory.state, false)
        }
        (_, Some((store_root, store_state))) => (store_root, store_state, true),
        (Some(memory), None) => (memory.state_root, memory.state, false),
        (None, None) => return Err(Error::HeadMissingFromSnapshotCache(head_block_root)),
    };

    if state.slot() > timer_target {
        record_timer_lag(current_slot, state.slot());
        return Ok(());
    }

    let initial_slot = state.slot();
    let initial_epoch = state.current_epoch();
    let mut slots_advanced: u64 = 0;
    let mut slots_persisted: u64 = 0;
    // The final slot was reached by a single-slot step that is still allowed to be written.
    let mut persist_final = false;

    while state.slot() < timer_target {
        let before = state.slot();
        if !persistable || before >= persist_limit {
            complete_state_advance(
                &mut state,
                Some(state_root),
                timer_target,
                beacon_chain.builder_onboarding_cache.as_deref(),
                &beacon_chain.spec,
            )
            .map_err(BeaconChainError::from)?;
            slots_advanced = slots_advanced
                .saturating_add(timer_target.as_u64().saturating_sub(before.as_u64()));
            persist_final = false;
            break;
        }

        if let Some(summary) = per_slot_processing(
            &mut state,
            Some(state_root),
            GloasVerificationContext::from_cache(beacon_chain.builder_onboarding_cache.as_deref()),
            &beacon_chain.spec,
        )
        .map_err(BeaconChainError::from)?
        {
            if let Err(e) = summary.observe_metrics() {
                error!(
                    src = "state_advance_timer",
                    error = ?e,
                    "Failed to observe epoch summary metrics"
                );
            }
            if state.current_epoch() + VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64
                >= current_slot.epoch(T::EthSpec::slots_per_epoch())
                && let Err(e) = beacon_chain
                    .validator_monitor
                    .read()
                    .process_validator_statuses(state.current_epoch(), &summary, &beacon_chain.spec)
            {
                error!(
                    error = ?e,
                    "Unable to process validator statuses"
                );
            }
        }
        slots_advanced = slots_advanced.saturating_add(1);
        state_root = state.update_tree_hash_cache()?;

        let reached_target = state.slot() >= timer_target;
        let reached_cap = state.slot() >= persist_limit;
        if !reached_target && !reached_cap {
            // Intermediate slot inside the cap. Persist it so the next step has a parent summary.
            beacon_chain.store.put_state(&state_root, &state)?;
            slots_persisted = slots_persisted.saturating_add(1);
            persist_final = false;
            continue;
        }
        if reached_cap && !reached_target {
            beacon_chain.store.put_state(&state_root, &state)?;
            slots_persisted = slots_persisted.saturating_add(1);
            let before_jump = state.slot();
            complete_state_advance(
                &mut state,
                Some(state_root),
                timer_target,
                beacon_chain.builder_onboarding_cache.as_deref(),
                &beacon_chain.spec,
            )
            .map_err(BeaconChainError::from)?;
            slots_advanced = slots_advanced
                .saturating_add(timer_target.as_u64().saturating_sub(before_jump.as_u64()));
            persist_final = false;
            break;
        }
        persist_final = true;
        break;
    }

    // Build committee caches on the final state and refresh the state root. Intermediate
    // persisted slots were hashed before these caches existed; the caches are not part of the
    // state root.
    state
        .build_committee_cache(RelativeEpoch::Current, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?;
    state
        .build_committee_cache(RelativeEpoch::Next, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?;
    let advanced_state_root = state.update_tree_hash_cache()?;

    if initial_epoch < state.current_epoch() {
        let current_epoch_decision_root = state.proposer_shuffling_decision_root_at_epoch(
            state.current_epoch(),
            head_block_root,
            &beacon_chain.spec,
        )?;
        beacon_chain.with_proposer_cache(
            current_epoch_decision_root,
            state.current_epoch(),
            |_| Ok(()),
            || {
                debug!(
                    shuffling_decision_root = ?current_epoch_decision_root,
                    epoch = %state.current_epoch(),
                    "Computing current epoch proposer shuffling in state advance"
                );
                Ok::<_, Error>((advanced_state_root, state.clone()))
            },
        )?;

        let next_epoch = state.next_epoch()?;
        let next_epoch_decision_slot = beacon_chain
            .spec
            .proposer_shuffling_decision_slot::<T::EthSpec>(next_epoch);
        if state.slot() > next_epoch_decision_slot {
            let next_epoch_decision_root = state.proposer_shuffling_decision_root_at_epoch(
                next_epoch,
                head_block_root,
                &beacon_chain.spec,
            )?;
            beacon_chain.with_proposer_cache(
                next_epoch_decision_root,
                next_epoch,
                |_| Ok(()),
                || {
                    debug!(
                        shuffling_decision_root = ?next_epoch_decision_root,
                        epoch = %next_epoch,
                        "Computing next epoch proposer shuffling in state advance"
                    );
                    Ok::<_, Error>((advanced_state_root, state.clone()))
                },
            )?;
        }

        let shuffling_id =
            AttestationShufflingId::new(head_block_root, &state, RelativeEpoch::Next)
                .map_err(BeaconChainError::from)?;
        let committee_cache = state
            .committee_cache(RelativeEpoch::Next)
            .map_err(BeaconChainError::from)?
            .clone();
        let shuffling_epoch = RelativeEpoch::Next.into_epoch(state.current_epoch());
        if let Some(ptcs) = CachedPTCs::try_from_state(&state, shuffling_epoch, &beacon_chain.spec)?
        {
            beacon_chain.shuffling_cache.write().insert_committee_cache(
                shuffling_id.clone(),
                CachedShuffling::new(committee_cache, ptcs),
            );
            debug!(
                ?head_block_root,
                next_epoch_shuffling_root = ?shuffling_id.shuffling_decision_block,
                state_epoch = %state.current_epoch(),
                current_epoch = %current_slot.epoch(T::EthSpec::slots_per_epoch()),
                "Primed proposer and attester caches"
            );
        } else {
            debug!(
                %shuffling_epoch,
                "Skipping priming of attester cache for Gloas boundary epoch"
            );
        }
    }

    let final_slot = state.slot();
    let starting_slot = current_slot;
    let current_slot = beacon_chain.slot()?;
    if starting_slot < current_slot {
        warn!(
            %head_block_root,
            advanced_slot = %final_slot,
            %current_slot,
            %starting_slot,
            msg = "system resources may be overloaded",
            "State advance too slow"
        );
    }

    if persist_final && final_slot <= persist_limit {
        beacon_chain.store.put_state(&advanced_state_root, &state)?;
        slots_persisted = slots_persisted.saturating_add(1);
    }

    beacon_chain
        .advanced_head_state
        .observe_complete_advanced_state(generation, head_block_root, advanced_state_root, &state);

    metrics::inc_counter_by(&metrics::STATE_ADVANCE_TIMER_SLOTS_ADVANCED, slots_advanced);
    metrics::inc_counter_by(
        &metrics::STATE_ADVANCE_TIMER_SLOTS_PERSISTED,
        slots_persisted,
    );
    record_timer_lag(current_slot, final_slot);

    debug!(
        ?head_block_root,
        advanced_slot = %final_slot,
        %initial_slot,
        %slots_advanced,
        %slots_persisted,
        "Completed state advance"
    );

    Ok(())
}

fn record_timer_lag(wall_clock_slot: Slot, advanced_slot: Slot) {
    let lag = wall_clock_slot.as_u64() as i64 - advanced_slot.as_u64() as i64;
    metrics::set_gauge(&metrics::STATE_ADVANCE_TIMER_SLOT_LAG, lag);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock() {
        let lock = Lock::new();
        assert!(!lock.lock());
        assert!(lock.lock());
        assert!(lock.lock());
        lock.unlock();
        assert!(!lock.lock());
        assert!(lock.lock());
    }
}

// The harness is too slow to build with debug assertions.
#[cfg(all(test, not(debug_assertions)))]
mod catch_up_tests {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use types::{EthSpec, Slot};

    type E = types::Spec;

    fn harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
        BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(E::slots_per_epoch() as usize)
            .fresh_ephemeral_store()
            .build()
    }

    #[test]
    fn catches_up_in_one_call_within_the_persistence_cap() {
        let harness = harness();
        let head_slot = harness.chain.best_slot();
        harness.set_current_slot(head_slot + 64);
        advance_head(&harness.chain, false).expect("advance");
        let wall = harness.chain.slot().unwrap();
        let head_root = harness.chain.canonical_head.cached_head().head_block_root();
        let stored = harness
            .chain
            .advanced_head_state
            .complete_seed(head_root, wall + 1)
            .expect("complete entry");
        assert_eq!(
            stored.state.slot(),
            wall + 1,
            "one timer call must catch the in-memory entry up to the timer target"
        );
    }

    #[test]
    fn past_the_cap_persists_only_max_distance_and_catches_memory_up() {
        let harness = harness();
        let head = harness.chain.canonical_head.cached_head();
        let head_slot = head.head_slot();
        let head_root = head.head_block_root();
        let head_state_root = head.head_state_root();
        harness.set_current_slot(head_slot + MAX_ADVANCE_DISTANCE + 64);
        advance_head(&harness.chain, false).expect("advance");
        let wall = harness.chain.slot().unwrap();
        let stored = harness
            .chain
            .advanced_head_state
            .complete_seed(head_root, wall + 1)
            .expect("complete entry");
        assert_eq!(stored.state.slot(), wall + 1);

        let (_, db_state) = harness
            .chain
            .store
            .get_advanced_hot_state(head_root, wall, head_state_root)
            .unwrap()
            .expect("persisted state");
        assert_eq!(db_state.slot(), head_slot + MAX_ADVANCE_DISTANCE);
        assert!(db_state.slot() < wall);
    }

    #[test]
    fn syncing_refuses_a_far_advance() {
        let harness = harness();
        let head_root = harness.chain.canonical_head.cached_head().head_block_root();
        let head_slot = harness.chain.best_slot();
        harness.set_current_slot(head_slot + MAX_ADVANCE_DISTANCE + 10);
        let err = advance_head(&harness.chain, true).unwrap_err();
        assert!(matches!(err, Error::MaxDistanceExceeded { .. }));
        assert!(
            harness
                .chain
                .advanced_head_state
                .complete_seed(head_root, Slot::new(u64::MAX))
                .is_none()
        );
    }
}
