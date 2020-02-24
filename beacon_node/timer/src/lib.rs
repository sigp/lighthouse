//! A timer service for the beacon node.
//!
//! This service allows task execution on the beacon node for various functionality.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, Stream};
use parking_lot::Mutex;
use slog::{debug, error, info, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{EthSpec, Slot};

/// A collection of timers that can execute actions on the beacon node.
///
/// This currently only has a per-slot timer, although others may be added in the future
struct Timer<T:BeachChainTypes> {
    /// Beacon chain associated.
    beacon_chain: Arc<BeaconChain<T>>,
    /// A timer that fires every slot.
    per_slot_timer: Interval,
    /// The logger for the timer.
    log: slog::Logger,
}

impl Timer {
    
    pub fn new(beacon_chain: Arc<BeaconCahin<T>>) -> Result<Self,_> {
        let duration_to_next_slot = beacon_chain.slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

        // A per-slot timer
        let start_instant = Instant::now() + duration_to_next_slot;
        let per_slot_timer = Interval::new(start_instant, slot_duration);

        Timer {
            beacon_chain
            per_slot_timer
        }
    }

    /// Tasks that occur on a per-slot basis.
    pub fn per_slot_task(&self) {
        beacon_chain.per_slot_task();
    }

    pub fn per_epoch_task(&self) {
        beacon_chain.per_epoch_task();
    }
}


/// Spawns a timer service which periodically executes tasks for the beacon chain
pub fn spawn<T: BeaconChainTypes>(
    context: RuntimeContext<T::EthSpec>,
    beacon_chain: Arc<BeaconChain<T>>,
    milliseconds_per_slot: u64,
) -> tokio::sync::oneshot::Sender<()> {

    let timer = Timer::new(beacon_chain);
    let (exit_signal, exit) = tokio::sync::oneshot::channel();

    executor.spawn(futures::future::poll_fn(move || -> Result<(),()> {

        if let Ok(Async::Ready(_)) | Err(_) = exit.poll() {
            // notifier is terminating, end the process
            return  Ok(Async::Ready(()));
        }

        while Async::Ready(_) = timer.per_slot_timer.poll().map_err(|| warn!(timer.log, "Per slot timer error"; "error" => format!("{:?}", e)))?  {
           timer.per_slot_task();
           if let Some(0) = timer.beacon_chain.slot_clock.now().map(|slot| slot%T::slots_per_epoch()) {
               timer.per_epoch_task();
           }
        }
        Ok(Async::NotReady)
    }));
}
