//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::stream::StreamExt;
use slog::info;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::time::{interval_at, Instant};

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn<T: BeaconChainTypes>(
    executor: environment::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
    log: slog::Logger,
) -> Result<(), &'static str> {
    let start_instant = Instant::now()
        + beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Warning: `interval_at` panics if `milliseconds_per_slot` = 0.
    let mut interval = interval_at(start_instant, Duration::from_millis(milliseconds_per_slot));
    let timer_future = async move {
        while interval.next().await.is_some() {
            beacon_chain.per_slot_task();
        }
    };

    executor.spawn(timer_future, "timer_service");
    info!(log, "Timer service started");

    Ok(())
}
