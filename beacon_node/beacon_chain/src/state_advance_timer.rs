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
use crate::validator_monitor::HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS;
use crate::{
    chain_config::FORK_CHOICE_LOOKAHEAD_FACTOR, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_slot_processing;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use store::KeyValueStore;
use task_executor::TaskExecutor;
use tokio::time::{sleep, sleep_until, Instant};
use types::{AttestationShufflingId, BeaconStateError, EthSpec, Hash256, RelativeEpoch, Slot};

/// If the head slot is more than `MAX_ADVANCE_DISTANCE` from the current slot, then don't perform
/// the state advancement.
///
/// This avoids doing unnecessary work whilst the node is syncing or has perhaps been put to sleep
/// for some period of time.
const MAX_ADVANCE_DISTANCE: u64 = 4;

/// Similarly for fork choice: avoid the fork choice lookahead during sync.
///
/// The value is set to 256 since this would be just over one slot (12.8s) when syncing at
/// 20 slots/second. Having a single fork-choice run interrupt syncing would have very little
/// impact whilst having 8 epochs without a block is a comfortable grace period.
const MAX_FORK_CHOICE_DISTANCE: u64 = 256;

#[derive(Debug)]
enum Error {
    BeaconChain(BeaconChainError),
    // We don't use the inner value directly, but it's used in the Debug impl.
    HeadMissingFromSnapshotCache(#[allow(dead_code)] Hash256),
    BeaconState(#[allow(dead_code)] BeaconStateError),
    Store(#[allow(dead_code)] store::Error),
    MaxDistanceExceeded {
        current_slot: Slot,
        head_slot: Slot,
    },
    StateAlreadyAdvanced {
        block_root: Hash256,
    },
    BadStateSlot {
        _state_slot: Slot,
        _block_slot: Slot,
    },
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Self::BeaconChain(e)
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
pub fn spawn_state_advance_timer<T: BeaconChainTypes>(
    executor: TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    log: Logger,
) {
    executor.spawn(
        state_advance_timer(executor.clone(), beacon_chain, log),
        "state_advance_timer",
    );
}

/// Provides the timer described in the module-level documentation.
async fn state_advance_timer<T: BeaconChainTypes>(
    executor: TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    log: Logger,
) {
    let is_running = Lock::new();
    let slot_clock = &beacon_chain.slot_clock;
    let slot_duration = slot_clock.slot_duration();

    loop {
        let Some(duration_to_next_slot) = beacon_chain.slot_clock.duration_to_next_slot() else {
            error!(log, "Failed to read slot clock");
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
                    log,
                    "Unable to determine slot in state advance timer";
                    "error" => ?e
                );
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
                continue;
            }
        };

        // Only spawn the state advance task if the lock was previously free.
        if !is_running.lock() {
            let log = log.clone();
            let beacon_chain = beacon_chain.clone();
            let is_running = is_running.clone();

            executor.spawn_blocking(
                move || {
                    match advance_head(&beacon_chain, &log) {
                        Ok(()) => (),
                        Err(Error::BeaconChain(e)) => error!(
                            log,
                            "Failed to advance head state";
                            "error" => ?e
                        ),
                        Err(Error::StateAlreadyAdvanced { block_root }) => debug!(
                            log,
                            "State already advanced on slot";
                            "block_root" => ?block_root
                        ),
                        Err(Error::MaxDistanceExceeded {
                            current_slot,
                            head_slot,
                        }) => debug!(
                            log,
                            "Refused to advance head state";
                            "head_slot" => head_slot,
                            "current_slot" => current_slot,
                        ),
                        other => warn!(
                            log,
                            "Did not advance head state";
                            "reason" => ?other
                        ),
                    };

                    // Permit this blocking task to spawn again, next time the timer fires.
                    is_running.unlock();
                },
                "state_advance_blocking",
            );
        } else {
            warn!(
                log,
                "State advance routine overloaded";
                "msg" => "system resources may be overloaded"
            )
        }

        // Run fork choice pre-emptively for the next slot. This processes most of the attestations
        // from this slot off the hot path of block verification and production.
        // Wait for the fork choice instant (which may already be past).
        sleep_until(fork_choice_instant).await;

        let log = log.clone();
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
                            log,
                            "Unable to prepare proposer with lookahead";
                            "error" => ?e,
                            "slot" => next_slot,
                        );
                        None
                    });

                // Use a blocking task to avoid blocking the core executor whilst waiting for locks
                // in `ForkChoiceSignalTx`.
                beacon_chain.task_executor.clone().spawn_blocking(
                    move || {
                        // Signal block proposal for the next slot (if it happens to be waiting).
                        if let Some(tx) = &beacon_chain.fork_choice_signal_tx {
                            if let Err(e) = tx.notify_fork_choice_complete(next_slot) {
                                warn!(
                                    log,
                                    "Error signalling fork choice waiter";
                                    "error" => ?e,
                                    "slot" => next_slot,
                                );
                            }
                        }
                    },
                    "fork_choice_advance_signal_tx",
                );
            },
            "fork_choice_advance",
        );
    }
}

/// Reads the `state_cache` from the `beacon_chain` and attempts to take a clone of the
/// `BeaconState` of the head block. If it obtains this clone, the state will be advanced a single
/// slot then placed in the `state_cache` to be used for block verification.
///
/// See the module-level documentation for rationale.
fn advance_head<T: BeaconChainTypes>(
    beacon_chain: &Arc<BeaconChain<T>>,
    log: &Logger,
) -> Result<(), Error> {
    let current_slot = beacon_chain.slot()?;

    // These brackets ensure that the `head_slot` value is dropped before we run fork choice and
    // potentially invalidate it.
    //
    // Fork-choice is not run *before* this function to avoid unnecessary calls whilst syncing.
    {
        let head_slot = beacon_chain.best_slot();

        // Don't run this when syncing or if lagging too far behind.
        if head_slot + MAX_ADVANCE_DISTANCE < current_slot {
            return Err(Error::MaxDistanceExceeded {
                current_slot,
                head_slot,
            });
        }
    }

    let (head_block_root, head_block_state_root) = {
        let snapshot = beacon_chain.head_snapshot();
        (snapshot.beacon_block_root, snapshot.beacon_state_root())
    };

    let (head_state_root, mut state) = beacon_chain
        .store
        .get_advanced_hot_state(head_block_root, current_slot, head_block_state_root)?
        .ok_or(Error::HeadMissingFromSnapshotCache(head_block_root))?;

    // Protect against advancing a state more than a single slot.
    //
    // Advancing more than one slot without storing the intermediate state would corrupt the
    // database. Future works might store temporary, intermediate states inside this function.
    match state.slot().cmp(&state.latest_block_header().slot) {
        std::cmp::Ordering::Equal => (),
        std::cmp::Ordering::Greater => {
            return Err(Error::StateAlreadyAdvanced {
                block_root: head_block_root,
            });
        }
        std::cmp::Ordering::Less => {
            return Err(Error::BadStateSlot {
                _block_slot: state.latest_block_header().slot,
                _state_slot: state.slot(),
            });
        }
    }

    let initial_slot = state.slot();
    let initial_epoch = state.current_epoch();

    // Advance the state a single slot.
    if let Some(summary) =
        per_slot_processing(&mut state, Some(head_state_root), &beacon_chain.spec)
            .map_err(BeaconChainError::from)?
    {
        // Expose Prometheus metrics.
        if let Err(e) = summary.observe_metrics() {
            error!(
                log,
                "Failed to observe epoch summary metrics";
                "src" => "state_advance_timer",
                "error" => ?e
            );
        }

        // Only notify the validator monitor for recent blocks.
        if state.current_epoch() + VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64
            >= current_slot.epoch(T::EthSpec::slots_per_epoch())
        {
            // Potentially create logs/metrics for locally monitored validators.
            if let Err(e) = beacon_chain
                .validator_monitor
                .read()
                .process_validator_statuses(state.current_epoch(), &summary, &beacon_chain.spec)
            {
                error!(
                    log,
                    "Unable to process validator statuses";
                    "error" => ?e
                );
            }
        }
    }

    debug!(
        log,
        "Advanced head state one slot";
        "head_block_root" => ?head_block_root,
        "state_slot" => state.slot(),
        "current_slot" => current_slot,
    );

    // Build the current epoch cache, to prepare to compute proposer duties.
    state
        .build_committee_cache(RelativeEpoch::Current, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?;
    // Build the next epoch cache, to prepare to compute attester duties.
    state
        .build_committee_cache(RelativeEpoch::Next, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?;

    // If the `pre_state` is in a later epoch than `state`, pre-emptively add the proposer shuffling
    // for the state's current epoch and the committee cache for the state's next epoch.
    if initial_epoch < state.current_epoch() {
        // Update the proposer cache.
        //
        // We supply the `head_block_root` as the decision block since the prior `if` statement guarantees
        // the head root is the latest block from the prior epoch.
        beacon_chain
            .beacon_proposer_cache
            .lock()
            .insert(
                state.current_epoch(),
                head_block_root,
                state
                    .get_beacon_proposer_indices(&beacon_chain.spec)
                    .map_err(BeaconChainError::from)?,
                state.fork(),
            )
            .map_err(BeaconChainError::from)?;

        // Update the attester cache.
        let shuffling_id =
            AttestationShufflingId::new(head_block_root, &state, RelativeEpoch::Next)
                .map_err(BeaconChainError::from)?;
        let committee_cache = state
            .committee_cache(RelativeEpoch::Next)
            .map_err(BeaconChainError::from)?;
        beacon_chain
            .shuffling_cache
            .write()
            .insert_committee_cache(shuffling_id.clone(), committee_cache);

        debug!(
            log,
            "Primed proposer and attester caches";
            "head_block_root" => ?head_block_root,
            "next_epoch_shuffling_root" => ?shuffling_id.shuffling_decision_block,
            "state_epoch" => state.current_epoch(),
            "current_epoch" => current_slot.epoch(T::EthSpec::slots_per_epoch()),
        );
    }

    // Apply the state to the attester cache, if the cache deems it interesting.
    beacon_chain
        .attester_cache
        .maybe_cache_state(&state, head_block_root, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?;

    let final_slot = state.slot();

    // If we have moved into the next slot whilst processing the state then this function is going
    // to become ineffective.
    //
    // If this warning occurs very frequently on well-resourced machines then we should consider
    // starting it earlier in the slot. Otherwise, it's a good indication that the machine is too
    // slow/overloaded and will be useful information for the user.
    let starting_slot = current_slot;
    let current_slot = beacon_chain.slot()?;
    if starting_slot < current_slot {
        warn!(
            log,
            "State advance too slow";
            "head_block_root" => %head_block_root,
            "advanced_slot" => final_slot,
            "current_slot" => current_slot,
            "starting_slot" => starting_slot,
            "msg" => "system resources may be overloaded",
        );
    }

    // Write the advanced state to the database with a temporary flag that will be deleted when
    // a block is imported on top of this state. We should delete this once we bring in the DB
    // changes from tree-states that allow us to prune states without temporary flags.
    let advanced_state_root = state.update_tree_hash_cache()?;
    let txn_lock = beacon_chain.store.hot_db.begin_rw_transaction();
    let state_already_exists = beacon_chain
        .store
        .load_hot_state_summary(&advanced_state_root)?
        .is_some();
    let temporary = !state_already_exists;
    beacon_chain
        .store
        .put_state_possibly_temporary(&advanced_state_root, &state, temporary)?;
    drop(txn_lock);

    debug!(
        log,
        "Completed state advance";
        "head_block_root" => ?head_block_root,
        "advanced_slot" => final_slot,
        "initial_slot" => initial_slot,
    );

    Ok(())
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
