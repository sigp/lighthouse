//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use slog::{info, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::time::sleep;

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn_timer<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
) -> Result<(), &'static str> {
    let log = executor.log().clone();
    let timer_future = async move {
        loop {
            let Some(duration_to_next_slot) = beacon_chain.slot_clock.duration_to_next_slot()
            else {
                warn!(log, "Unable to determine duration to next slot");
                return;
            };

            sleep(duration_to_next_slot).await;
            beacon_chain.per_slot_task().await;
        }
    };

    executor.spawn(timer_future, "timer");
    info!(executor.log(), "Timer service started");

    Ok(())
}
