//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use slot_clock::SlotClock;
use std::sync::Arc;
use tracing::{info, warn};

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn_timer<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
) -> Result<(), &'static str> {
    let timer_future = async move {
        loop {
            if !beacon_chain.slot_clock.sleep_until_next_slot().await {
                warn!("Unable to determine duration to next slot");
                return;
            }

            beacon_chain.per_slot_task().await;
        }
    };

    executor.spawn(timer_future, "timer");
    info!("Timer service started");

    Ok(())
}
