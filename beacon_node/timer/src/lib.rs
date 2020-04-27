//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::{future, prelude::*};
use slog::error;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn<T: BeaconChainTypes>(
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
    log: slog::Logger,
) -> Result<tokio::sync::oneshot::Sender<()>, &'static str> {
    let (exit_signal, exit) = tokio::sync::oneshot::channel();

    let start_instant = Instant::now()
        + beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    let timer_future = Interval::new(start_instant, Duration::from_millis(milliseconds_per_slot))
        .map_err(move |e| {
            error!(
                log,
                "Beacon chain timer failed";
                "error" => format!("{:?}", e)
            )
        })
        .for_each(move |_| {
            beacon_chain.per_slot_task();
            future::ok(())
        });

    executor.spawn(
        exit.map_err(|_| ())
            .select(timer_future)
            .map(|_| ())
            .map_err(|_| ()),
    );

    Ok(exit_signal)
}
