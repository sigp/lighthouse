use crate::metrics;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::NetworkGlobals;
use parking_lot::Mutex;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use types::{EthSpec, Slot};

/// Create a warning log whenever the peer count is at or below this value.
pub const WARN_PEER_COUNT: usize = 1;

const DAYS_PER_WEEK: i64 = 7;
const HOURS_PER_DAY: i64 = 24;
const MINUTES_PER_HOUR: i64 = 60;

/// The number of historical observations that should be used to determine the average sync time.
const SPEEDO_OBSERVATIONS: usize = 4;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network: Arc<NetworkGlobals<T::EthSpec>>,
    seconds_per_slot: u64,
) -> Result<(), String> {
    let slot_duration = Duration::from_secs(seconds_per_slot);
    let duration_to_next_slot = beacon_chain
        .slot_clock
        .duration_to_next_slot()
        .ok_or("slot_notifier unable to determine time to next slot")?;

    // Run this half way through each slot.
    let start_instant = tokio::time::Instant::now() + duration_to_next_slot + (slot_duration / 2);

    // Run this each slot.
    let interval_duration = slot_duration;

    let speedo = Mutex::new(Speedo::default());
    let log = executor.log().clone();
    let mut interval = tokio::time::interval_at(start_instant, interval_duration);

    let interval_future = async move {
        // Perform pre-genesis logging.
        loop {
            match beacon_chain.slot_clock.duration_to_next_slot() {
                // If the duration to the next slot is greater than the slot duration, then we are
                // waiting for genesis.
                Some(next_slot) if next_slot > slot_duration => {
                    info!(
                        log,
                        "Waiting for genesis";
                        "peers" => peer_count_pretty(network.connected_peers()),
                        "wait_time" => estimated_time_pretty(Some(next_slot.as_secs() as f64)),
                    );
                    eth1_logging(&beacon_chain, &log);
                    sleep(slot_duration).await;
                }
                _ => break,
            }
        }

        // Perform post-genesis logging.
        loop {
            interval.tick().await;
            let connected_peer_count = network.connected_peers();
            let sync_state = network.sync_state();

            let head_info = match beacon_chain.head_info() {
                Ok(head_info) => head_info,
                Err(e) => {
                    error!(log, "Failed to get beacon chain head info"; "error" => format!("{:?}", e));
                    break;
                }
            };

            let head_slot = head_info.slot;

            metrics::set_gauge(&metrics::NOTIFIER_HEAD_SLOT, head_slot.as_u64() as i64);

            let current_slot = match beacon_chain.slot() {
                Ok(slot) => slot,
                Err(e) => {
                    error!(
                        log,
                        "Unable to read current slot";
                        "error" => format!("{:?}", e)
                    );
                    break;
                }
            };

            let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
            let finalized_epoch = head_info.finalized_checkpoint.epoch;
            let finalized_root = head_info.finalized_checkpoint.root;
            let head_root = head_info.block_root;

            let mut speedo = speedo.lock();
            speedo.observe(head_slot, Instant::now());

            metrics::set_gauge(
                &metrics::SYNC_SLOTS_PER_SECOND,
                speedo.slots_per_second().unwrap_or(0_f64) as i64,
            );

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
                metrics::set_gauge(&metrics::IS_SYNCED, 0);
                let distance = format!(
                    "{} slots ({})",
                    head_distance.as_u64(),
                    slot_distance_pretty(head_distance, slot_duration)
                );

                let speed = speedo.slots_per_second();
                let display_speed = speed.map_or(false, |speed| speed != 0.0);

                if display_speed {
                    info!(
                        log,
                        "Syncing";
                        "peers" => peer_count_pretty(connected_peer_count),
                        "distance" => distance,
                        "speed" => sync_speed_pretty(speed),
                        "est_time" => estimated_time_pretty(speedo.estimated_time_till_slot(current_slot)),
                    );
                } else {
                    info!(
                        log,
                        "Syncing";
                        "peers" => peer_count_pretty(connected_peer_count),
                        "distance" => distance,
                        "est_time" => estimated_time_pretty(speedo.estimated_time_till_slot(current_slot)),
                    );
                }
            } else if sync_state.is_synced() {
                metrics::set_gauge(&metrics::IS_SYNCED, 1);
                let block_info = if current_slot > head_slot {
                    "   …  empty".to_string()
                } else {
                    head_root.to_string()
                };
                info!(
                    log,
                    "Synced";
                    "peers" => peer_count_pretty(connected_peer_count),
                    "finalized_root" => format!("{}", finalized_root),
                    "finalized_epoch" => finalized_epoch,
                    "epoch" => current_epoch,
                    "block" => block_info,
                    "slot" => current_slot,
                );
            } else {
                metrics::set_gauge(&metrics::IS_SYNCED, 0);
                info!(
                    log,
                    "Searching for peers";
                    "peers" => peer_count_pretty(connected_peer_count),
                    "finalized_root" => format!("{}", finalized_root),
                    "finalized_epoch" => finalized_epoch,
                    "head_slot" => head_slot,
                    "current_slot" => current_slot,
                );
            }

            eth1_logging(&beacon_chain, &log);
        }
    };

    // run the notifier on the current executor
    executor.spawn(interval_future, "notifier");

    Ok(())
}

fn eth1_logging<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>, log: &Logger) {
    let current_slot_opt = beacon_chain.slot().ok();

    if let Ok(head_info) = beacon_chain.head_info() {
        // Perform some logging about the eth1 chain
        if let Some(eth1_chain) = beacon_chain.eth1_chain.as_ref() {
            if let Some(status) =
                eth1_chain.sync_status(head_info.genesis_time, current_slot_opt, &beacon_chain.spec)
            {
                debug!(
                    log,
                    "Eth1 cache sync status";
                    "eth1_head_block" => status.head_block_number,
                    "latest_cached_block_number" => status.latest_cached_block_number,
                    "latest_cached_timestamp" => status.latest_cached_block_timestamp,
                    "voting_target_timestamp" => status.voting_target_timestamp,
                    "ready" => status.lighthouse_is_cached_and_ready
                );

                if !status.lighthouse_is_cached_and_ready {
                    let voting_target_timestamp = status.voting_target_timestamp;

                    let distance = status
                        .latest_cached_block_timestamp
                        .map(|latest| {
                            voting_target_timestamp.saturating_sub(latest)
                                / beacon_chain.spec.seconds_per_eth1_block
                        })
                        .map(|distance| distance.to_string())
                        .unwrap_or_else(|| "initializing deposits".to_string());

                    warn!(
                        log,
                        "Syncing eth1 block cache";
                        "msg" => "sync can take longer when using remote eth1 nodes",
                        "est_blocks_remaining" => distance,
                    );
                }
            } else {
                error!(
                    log,
                    "Unable to determine eth1 sync status";
                );
            }
        }
    } else {
        error!(
            log,
            "Unable to get head info";
        );
    }
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

    let d = time::Duration::seconds_f64(secs);

    let weeks = d.whole_weeks();
    let days = d.whole_days();
    let hours = d.whole_hours();
    let minutes = d.whole_minutes();

    let week_string = if weeks == 1 { "week" } else { "weeks" };
    let day_string = if days == 1 { "day" } else { "days" };
    let hour_string = if hours == 1 { "hr" } else { "hrs" };
    let min_string = if minutes == 1 { "min" } else { "mins" };

    if weeks > 0 {
        format!(
            "{:.0} {} {:.0} {}",
            weeks,
            week_string,
            days % DAYS_PER_WEEK,
            day_string
        )
    } else if days > 0 {
        format!(
            "{:.0} {} {:.0} {}",
            days,
            day_string,
            hours % HOURS_PER_DAY,
            hour_string
        )
    } else if hours > 0 {
        format!(
            "{:.0} {} {:.0} {}",
            hours,
            hour_string,
            minutes % MINUTES_PER_HOUR,
            min_string
        )
    } else {
        format!("{:.0} {}", minutes, min_string)
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
