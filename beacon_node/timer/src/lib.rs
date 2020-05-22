//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::future;
use futures::stream::StreamExt;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::time::{interval_at, Instant};

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn<T: BeaconChainTypes>(
    handle: &Handle,
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
) -> Result<tokio::sync::oneshot::Sender<()>, &'static str> {
    let (exit_signal, exit) = tokio::sync::oneshot::channel();

    let start_instant = Instant::now()
        + beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Warning: `interval_at` panics if `milliseconds_per_slot` = 0.
    let timer_future = interval_at(start_instant, Duration::from_millis(milliseconds_per_slot))
        .for_each(move |_| {
            beacon_chain.per_slot_task();
            future::ready(())
        });

    let future = futures::future::select(timer_future, exit);
    handle.spawn(future);

    Ok(exit_signal)
}
