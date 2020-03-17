//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::prelude::*;
use slog::warn;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::EthSpec;

/// A collection of timers that can execute actions on the beacon node.
///
/// This currently only has a per-slot timer, although others may be added in the future
struct Timer<T: BeaconChainTypes> {
    /// Beacon chain associated.
    beacon_chain: Arc<BeaconChain<T>>,
    /// A timer that fires every slot.
    per_slot_timer: Interval,
    /// The logger for the timer.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> Timer<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        milliseconds_per_slot: u64,
        log: slog::Logger,
    ) -> Result<Self, &'static str> {
        let duration_to_next_slot = beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

        let slot_duration = Duration::from_millis(milliseconds_per_slot);
        // A per-slot timer
        let start_instant = Instant::now() + duration_to_next_slot;
        let per_slot_timer = Interval::new(start_instant, slot_duration);

        Ok(Timer {
            beacon_chain,
            per_slot_timer,
            log,
        })
    }

    /// Tasks that occur on a per-slot basis.
    pub fn per_slot_task(&self) {
        self.beacon_chain.per_slot_task();
    }

    pub fn per_epoch_task(&self) {
        self.beacon_chain.per_epoch_task();
    }
}

/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn<T: BeaconChainTypes>(
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
    log: slog::Logger,
) -> Result<tokio::sync::oneshot::Sender<()>, &'static str> {
    //let thread_log = log.clone();
    let mut timer = Timer::new(beacon_chain, milliseconds_per_slot, log)?;
    let (exit_signal, mut exit) = tokio::sync::oneshot::channel();

    executor.spawn(futures::future::poll_fn(move || -> Result<_, ()> {
        if let Ok(Async::Ready(_)) | Err(_) = exit.poll() {
            // notifier is terminating, end the process
            return Ok(Async::Ready(()));
        }

        while let Async::Ready(_) = timer
            .per_slot_timer
            .poll()
            .map_err(|e| warn!(timer.log, "Per slot timer error"; "error" => format!("{:?}", e)))?
        {
            timer.per_slot_task();
            match timer
                .beacon_chain
                .slot_clock
                .now()
                .map(|slot| (slot % T::EthSpec::slots_per_epoch()).as_u64())
            {
                Some(0) => timer.per_epoch_task(),
                _ => {}
            }
        }
        Ok(Async::NotReady)
    }));

    Ok(exit_signal)
}
