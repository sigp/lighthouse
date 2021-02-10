use crate::validator_monitor::HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS;
use crate::{
    beacon_chain::BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, BeaconChain, BeaconChainError,
    BeaconChainTypes,
};
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_slot_processing;
use std::sync::Arc;
use tokio::time::sleep;
use types::{EthSpec, Hash256, Slot};

const MAX_ADVANCE_DISTANCE: u64 = 4;

#[derive(Debug)]
enum Error {
    BeaconChain(BeaconChainError),
    HeadMissingFromSnapshotCache(Hash256),
    MaxDistanceExceeded { target_slot: Slot, head_slot: Slot },
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Self::BeaconChain(e)
    }
}

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
            Err(Error::MaxDistanceExceeded {
                target_slot,
                head_slot,
            }) => debug!(
                log,
                "Refused to advance head state";
                "head_slot" => head_slot,
                "target_slot" => target_slot,
            ),
            other => warn!(
                log,
                "Did not advance head state";
                "reason" => ?other
            ),
        };
    }
}

fn advance_head<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    log: &Logger,
) -> Result<(), Error> {
    let current_slot = beacon_chain.slot()?;
    let target_slot = current_slot + 1;
    let precondition_slot = beacon_chain.head_info()?.slot;

    // Don't run this when syncing.
    if precondition_slot + MAX_ADVANCE_DISTANCE < target_slot {
        return Err(Error::MaxDistanceExceeded {
            target_slot,
            head_slot: precondition_slot,
        });
    }

    // Run fork choice so we get the lastest view of the head.
    beacon_chain.fork_choice()?;

    let head_root = beacon_chain.head_info()?.block_root;

    let (head_slot, head_state_root, mut state) = beacon_chain
        .snapshot_cache
        .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::SnapshotCacheLockTimeout)?
        .get_for_state_advance(head_root)
        .ok_or_else(|| Error::HeadMissingFromSnapshotCache(head_root))?;

    let initial_slot = state.slot;
    let initial_epoch = state.current_epoch();

    while state.slot < target_slot {
        // Advance a single slot on `pre_state`.
        //
        // This is an optimisation with the following benefits:
        //
        // 1. When following head (i.e., not syncing), this means that we can use the tail-end of
        //    slot `n` to compute the pre-state for the block at slot `n + 1`. This allows us to
        //    import blocks faster ("import" meaning placed in the DB and fork choice, not
        //    necessarily the completion of this function).
        // 2. On epoch boundaries, it allows us to learn the proposer shuffling for the next epoch
        //    and prime our caches. This shortens block propagation verification times, since we
        //    don't need to compute the shuffling.
        //
        // The downside of this optimization is that we now need to hold two copies of the state;
        // one that is advanced to the next state (`pre_state`) and one that is not (`state`). We
        // maintain the non-advanced `state` to avoid a DB read when setting an imported block as
        // the head and therefore putting the state in `self.canonical_head`.
        let state_root = if state.slot == head_slot {
            Some(head_state_root)
        } else {
            None
        };
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
            "target_slot" => target_slot,
        );
    }

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
