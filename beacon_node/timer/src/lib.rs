//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::stream::{StreamExt};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::time::{interval_at, Instant};

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub async fn spawn<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
) -> Result<tokio::sync::oneshot::Sender<()>, &'static str> {
    let (exit_signal, mut exit) = tokio::sync::oneshot::channel();

    let start_instant = Instant::now()
        + beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Warning: `interval_at` panics on error
    let mut timer_future = interval_at(start_instant, Duration::from_millis(milliseconds_per_slot));
    let timer_future = async move {
        while let Some(_) = timer_future.next().await {
            beacon_chain.per_slot_task();
            match exit.try_recv() {
                Ok(_) | Err(TryRecvError::Closed) => break,
                Err(TryRecvError::Empty) => {}
            }
        }
    };

    tokio::task::spawn(timer_future);

    Ok(exit_signal)
}
