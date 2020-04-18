use crate::metrics;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use environment::RuntimeContext;
use eth2_libp2p::NetworkGlobals;
use futures::{Future, Stream};
use parking_lot::Mutex;
use slog::{debug, error, info, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{EthSpec, Slot};

/// Create a warning log whenever the peer count is at or below this value.
pub const WARN_PEER_COUNT: usize = 1;

const SECS_PER_MINUTE: f64 = 60.0;
const SECS_PER_HOUR: f64 = 3600.0;
const SECS_PER_DAY: f64 = 86400.0; // non-leap
const SECS_PER_WEEK: f64 = 604_800.0; // non-leap
const DAYS_PER_WEEK: f64 = 7.0;
const HOURS_PER_DAY: f64 = 24.0;
const MINUTES_PER_HOUR: f64 = 60.0;

/// The number of historical observations that should be used to determine the average sync time.
const SPEEDO_OBSERVATIONS: usize = 4;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: BeaconChainTypes>(
    context: RuntimeContext<T::EthSpec>,
    beacon_chain: Arc<BeaconChain<T>>,
    network: Arc<NetworkGlobals<T::EthSpec>>,
    milliseconds_per_slot: u64,
) -> Result<tokio::sync::oneshot::Sender<()>, String> {
    let log_1 = context.log.clone();
    let log_2 = context.log.clone();
    let log_3 = context.log.clone();

    let slot_duration = Duration::from_millis(milliseconds_per_slot);
    let duration_to_next_slot = beacon_chain
        .slot_clock
        .duration_to_next_slot()
        .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Run this half way through each slot.
    let start_instant = Instant::now() + duration_to_next_slot + (slot_duration / 2);

    // Run this each slot.
    let interval_duration = slot_duration;

    let speedo = Mutex::new(Speedo::default());

    let interval_future = Interval::new(start_instant, interval_duration)
        .map_err(
            move |e| error!(log_1, "Slot notifier timer failed"; "error" => format!("{:?}", e)),
        )
        .for_each(move |_| {
            let log = log_2.clone();

            let connected_peer_count = network.connected_peers();
            let sync_state = network.sync_state();

            let head_info = beacon_chain.head_info()
                .map_err(|e| error!(
                    log,
                    "Failed to get beacon chain head info";
                    "error" => format!("{:?}", e)
                ))?;

            let head_slot = head_info.slot;
            let current_slot = beacon_chain.slot().map_err(|e| {
                error!(
                    log,
                    "Unable to read current slot";
                    "error" => format!("{:?}", e)
                )
            })?;
            let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
            let finalized_epoch = head_info.finalized_checkpoint.epoch;
            let finalized_root = head_info.finalized_checkpoint.root;
            let head_root = head_info.block_root;

            let mut speedo = speedo.lock();
            speedo.observe(head_slot, Instant::now());

            metrics::set_gauge(&metrics::SYNC_SLOTS_PER_SECOND, speedo.slots_per_second().unwrap_or_else(|| 0_f64) as i64);

            // The next two lines take advantage of saturating subtraction on `Slot`.
            let head_distance = current_slot - head_slot;

            if connected_peer_count <= WARN_PEER_COUNT {
                warn!(log, "Low peer count"; "peer_count" => peer_count_pretty(connected_peer_count));
            }

            debug!(
                log,
                "Slot timer";
                "peers" => peer_count_pretty(connected_peer_count),
                "finalized_root" => format!("{}", finalized_root),
                "finalized_epoch" => finalized_epoch,
                "head_block" => format!("{}", head_root),
                "head_slot" => head_slot,
                "current_slot" => current_slot,
                "sync_state" =>format!("{}", sync_state) 
            );


            // Log if we are syncing
            if sync_state.is_syncing() {
                let distance = format!(
                    "{} slots ({})",
                    head_distance.as_u64(),
                    slot_distance_pretty(head_distance, slot_duration)
                );
                info!(
                    log,
                    "Syncing";
                    "peers" => peer_count_pretty(connected_peer_count),
                    "distance" => distance,
                    "speed" => sync_speed_pretty(speedo.slots_per_second()),
                    "est_time" => estimated_time_pretty(speedo.estimated_time_till_slot(current_slot)),
                );
            } else {
                if sync_state.is_synced() { 
                    info!(
                        log_2,
                        "Synced";
                        "peers" => peer_count_pretty(connected_peer_count),
                        "finalized_root" => format!("{}", finalized_root),
                        "finalized_epoch" => finalized_epoch,
                        "epoch" => current_epoch,
                        "slot" => current_slot,
                    );
                } else { 
                    info!(
                        log_2,
                        "Searching for peers";
                        "peers" => peer_count_pretty(connected_peer_count),
                        "finalized_root" => format!("{}", finalized_root),
                        "finalized_epoch" => finalized_epoch,
                        "head_slot" => head_slot,
                        "current_slot" => current_slot,
                    );
                }
            }
            Ok(())
        })
        .then(move |result| {
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    error!(
                    log_3,
                    "Notifier failed to notify";
                    "error" => format!("{:?}", e)
                );
                Ok(())
            } } });

    let (exit_signal, exit) = tokio::sync::oneshot::channel();

    context
        .executor
        .spawn(interval_future.select(exit).map(|_| ()).map_err(|_| ()));

    Ok(exit_signal)
}

/// Returns the peer count, returning something helpful if it's `usize::max_value` (effectively a
/// `None` value).
fn peer_count_pretty(peer_count: usize) -> String {
    if peer_count == usize::max_value() {
        String::from("--")
    } else {
        format!("{}", peer_count)
    }
}

/// Returns a nicely formatted string describing the rate of slot imports per second.
fn sync_speed_pretty(slots_per_second: Option<f64>) -> String {
    if let Some(slots_per_second) = slots_per_second {
        format!("{:.2} slots/sec", slots_per_second)
    } else {
        "--".into()
    }
}

/// Returns a nicely formatted string how long will we reach the target slot.
fn estimated_time_pretty(seconds_till_slot: Option<f64>) -> String {
    if let Some(seconds_till_slot) = seconds_till_slot {
        seconds_pretty(seconds_till_slot)
    } else {
        "--".into()
    }
}

/// Returns a nicely formatted string describing the `slot_span` in terms of weeks, days, hours
/// and/or minutes.
fn slot_distance_pretty(slot_span: Slot, slot_duration: Duration) -> String {
    if slot_duration == Duration::from_secs(0) {
        return String::from("Unknown");
    }

    let secs = (slot_duration * slot_span.as_u64() as u32).as_secs();
    seconds_pretty(secs as f64)
}

/// Returns a nicely formatted string describing the `slot_span` in terms of weeks, days, hours
/// and/or minutes.
fn seconds_pretty(secs: f64) -> String {
    if secs <= 0.0 {
        return "--".into();
    }

    let weeks = secs / SECS_PER_WEEK;
    let days = secs / SECS_PER_DAY;
    let hours = secs / SECS_PER_HOUR;
    let minutes = secs / SECS_PER_MINUTE;

    if weeks.floor() > 0.0 {
        format!(
            "{:.0} weeks {:.0} days",
            weeks,
            (days % DAYS_PER_WEEK).round()
        )
    } else if days.floor() > 0.0 {
        format!(
            "{:.0} days {:.0} hrs",
            days,
            (hours % HOURS_PER_DAY).round()
        )
    } else if hours.floor() > 0.0 {
        format!(
            "{:.0} hrs {:.0} mins",
            hours,
            (minutes % MINUTES_PER_HOUR).round()
        )
    } else {
        format!("{:.0} mins", minutes.round())
    }
}

/// "Speedo" is Australian for speedometer. This struct observes syncing times.
#[derive(Default)]
pub struct Speedo(Vec<(Slot, Instant)>);

impl Speedo {
    /// Observe that we were at some `slot` at the given `instant`.
    pub fn observe(&mut self, slot: Slot, instant: Instant) {
        if self.0.len() > SPEEDO_OBSERVATIONS {
            self.0.remove(0);
        }

        self.0.push((slot, instant));
    }

    /// Returns the average of the speeds between each observation.
    ///
    /// Does not gracefully handle slots that are above `u32::max_value()`.
    pub fn slots_per_second(&self) -> Option<f64> {
        let speeds = self
            .0
            .windows(2)
            .filter_map(|windows| {
                let (slot_a, instant_a) = windows[0];
                let (slot_b, instant_b) = windows[1];

                // Taking advantage of saturating subtraction on `Slot`.
                let distance = f64::from((slot_b - slot_a).as_u64() as u32);

                let seconds = f64::from((instant_b - instant_a).as_millis() as u32) / 1_000.0;

                if seconds > 0.0 {
                    Some(distance / seconds)
                } else {
                    None
                }
            })
            .collect::<Vec<f64>>();

        let count = speeds.len();
        let sum: f64 = speeds.iter().sum();

        if count > 0 {
            Some(sum / f64::from(count as u32))
        } else {
            None
        }
    }

    /// Returns the time we should reach the given `slot`, judging by the latest observation and
    /// historical average syncing time.
    ///
    /// Returns `None` if the slot is prior to our latest observed slot or we have not made any
    /// observations.
    pub fn estimated_time_till_slot(&self, target_slot: Slot) -> Option<f64> {
        let (prev_slot, _) = self.0.last()?;
        let slots_per_second = self.slots_per_second()?;

        if target_slot > *prev_slot && slots_per_second > 0.0 {
            let distance = (target_slot - *prev_slot).as_u64() as f64;
            Some(distance / slots_per_second)
        } else {
            None
        }
    }
}
