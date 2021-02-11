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
    beacon_chain::BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, snapshot_cache::StateAdvance, BeaconChain,
    BeaconChainError, BeaconChainTypes,
};
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_slot_processing;
use std::sync::Arc;
use tokio::time::sleep;
use types::{EthSpec, Hash256, Slot};

/// If the head slot is more than `MAX_ADAVANCE_DISTANCE` from the current slot, then don't perform
/// the state advancement.
///
/// This avoids doing unnecessary work whilst the node is syncing or has perhaps been put to sleep
/// for some period of time.
const MAX_ADVANCE_DISTANCE: u64 = 4;

#[derive(Debug)]
enum Error {
    BeaconChain(BeaconChainError),
    HeadMissingFromSnapshotCache(Hash256),
    MaxDistanceExceeded { current_slot: Slot, head_slot: Slot },
    StateAlreadyAdvanced { block_root: Hash256 },
    BadStateSlot { state_slot: Slot, block_slot: Slot },
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Self::BeaconChain(e)
    }
}

/// Spawns the timer described in the module-level documentation.
pub fn spawn_state_advance_timer<T: BeaconChainTypes>(
    executor: &task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    log: Logger,
) {
    executor.spawn(
        state_advance_timer(beacon_chain, log),
        "state_advance_timer",
    );
}

/// Provides the timer described in the module-level documentation.
async fn state_advance_timer<T: BeaconChainTypes>(beacon_chain: Arc<BeaconChain<T>>, log: Logger) {
    let slot_clock = &beacon_chain.slot_clock;
    let slot_duration = slot_clock.slot_duration();

    loop {
        let delay = match beacon_chain.slot_clock.duration_to_next_slot() {
            Some(duration) => duration + (slot_duration / 4) * 3,
            None => {
                error!(log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                slot_duration
            }
        };

        // Wait until we should fire an event.
        sleep(delay).await;

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
    }
}

/// Reads the `snapshot_cache` from the `beacon_chain` and attempts to take a clone of the
/// `BeaconState` of the head block. If it obtains this clone, the state will be advanced a single
/// slot then placed back in the `snapshot_cache` to be used for block verification.
///
/// See the module-level documentation for rationale.
fn advance_head<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    log: &Logger,
) -> Result<(), Error> {
    let current_slot = beacon_chain.slot()?;

    // These brackets ensure that the `head_slot` value is dropped before we run fork choice and
    // potentially invalidate it.
    //
    // Fork-choice is not run *before* this function to avoid unnecessary calls whilst syncing.
    {
        let head_slot = beacon_chain.head_info()?.slot;

        // Don't run this when syncing or if lagging too far behind.
        if head_slot + MAX_ADVANCE_DISTANCE < current_slot {
            return Err(Error::MaxDistanceExceeded {
                current_slot,
                head_slot,
            });
        }
    }

    // Run fork choice so we get the latest view of the head.
    //
    // This is useful since it's quite likely that the last time we ran fork choice was shortly
    // after receiving the latest gossip block, but not necessarily after we've received the
    // majority of attestations.
    beacon_chain.fork_choice()?;

    let head_root = beacon_chain.head_info()?.block_root;

    let (head_slot, head_state_root, mut state) = match beacon_chain
        .snapshot_cache
        .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::SnapshotCacheLockTimeout)?
        .get_for_state_advance(head_root)
    {
        StateAdvance::AlreadyAdvanced => {
            return Err(Error::StateAlreadyAdvanced {
                block_root: head_root,
            })
        }
        StateAdvance::BlockNotFound => return Err(Error::HeadMissingFromSnapshotCache(head_root)),
        StateAdvance::State {
            state,
            state_root,
            block_slot,
        } => (block_slot, state_root, state),
    };

    let initial_slot = state.slot;
    let initial_epoch = state.current_epoch();

    let state_root = if state.slot == head_slot {
        Some(head_state_root)
    } else {
        // Protect against advancing a state more than a single slot.
        //
        // Advancing more than one slot without storing the intermediate state would corrupt the
        // database. Future works might store temporary, intermediate states inside this function.
        return Err(Error::BadStateSlot {
            block_slot: head_slot,
            state_slot: state.slot,
        });
    };

    // Advance the state a single slot.
    if let Some(summary) = per_slot_processing(&mut state, state_root, &beacon_chain.spec)
        .map_err(BeaconChainError::from)?
    {
        // Only notify the validator monitor for recent blocks.
        if state.current_epoch() + VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64
            >= current_slot.epoch(T::EthSpec::slots_per_epoch())
        {
            // Potentially create logs/metrics for locally monitored validators.
            beacon_chain
                .validator_monitor
                .read()
                .process_validator_statuses(state.current_epoch(), &summary.statuses);
        }
    }

    debug!(
        log,
        "Advanced head state one slot";
        "head_root" => ?head_root,
        "state_slot" => state.slot,
        "current_slot" => current_slot,
    );

    // If the `pre_state` is in a later epoch than `state`, pre-emptively add the proposer
    // shuffling for the next epoch into the cache.
    if initial_epoch > state.current_epoch() {
        debug!(
            log,
            "Priming proposer cache";
            "head_root" => ?head_root,
            "state_epoch" => state.current_epoch(),
            "current_epoch" => current_slot.epoch(T::EthSpec::slots_per_epoch()),
        );
        beacon_chain
            .beacon_proposer_cache
            .write()
            .insert(
                state.current_epoch(),
                head_root,
                state
                    .get_beacon_proposer_indices(&beacon_chain.spec)
                    .map_err(BeaconChainError::from)?,
                state.fork,
            )
            .map_err(BeaconChainError::from)?;
    }

    let final_slot = state.slot;

    // Insert the advanced state back into the snapshot cache.
    beacon_chain
        .snapshot_cache
        .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::SnapshotCacheLockTimeout)?
        .update_pre_state(head_root, state)
        .ok_or_else(|| Error::HeadMissingFromSnapshotCache(head_root))?;

    let current_slot = beacon_chain.slot()?;
    if final_slot <= current_slot {
        warn!(
            log,
            "State advance too slow";
            "head_root" => %head_root,
            "advanced_slot" => final_slot,
            "current_slot" => current_slot,
            "initial_slot" => initial_slot,
            "msg" => "system may be overloaded",
        );
    }

    debug!(
        log,
        "Completed state advance";
        "head_root" => ?head_root,
        "advanced_slot" => final_slot,
        "initial_slot" => initial_slot,
    );

    Ok(())
}
