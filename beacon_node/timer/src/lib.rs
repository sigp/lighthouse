//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use slog::info;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval_at, Instant};

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn_timer<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    seconds_per_slot: u64,
) -> Result<(), &'static str> {
    let log = executor.log();
    let start_instant = Instant::now()
        + beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or("slot_notifier unable to determine time to next slot")?;

    // Warning: `interval_at` panics if `seconds_per_slot` = 0.
    let mut interval = interval_at(start_instant, Duration::from_secs(seconds_per_slot));
    let per_slot_executor = executor.clone();
    let timer_future = async move {
        loop {
            interval.tick().await;
            let chain = beacon_chain.clone();
            per_slot_executor.spawn_blocking(move || chain.per_slot_task(), "timer_per_slot_task");
        }
    };

    executor.spawn(timer_future, "timer");
    info!(log, "Timer service started");

    Ok(())
}
