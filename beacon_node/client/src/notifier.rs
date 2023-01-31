use crate::metrics;
use beacon_chain::{
    capella_readiness::CapellaReadiness,
    merge_readiness::{MergeConfig, MergeReadiness},
    BeaconChain, BeaconChainTypes, ExecutionStatus,
};
use lighthouse_network::{types::SyncState, NetworkGlobals};
use slog::{crit, debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use types::*;

/// Create a warning log whenever the peer count is at or below this value.
pub const WARN_PEER_COUNT: usize = 1;

const DAYS_PER_WEEK: i64 = 7;
const HOURS_PER_DAY: i64 = 24;
const MINUTES_PER_HOUR: i64 = 60;

/// The number of historical observations that should be used to determine the average sync time.
const SPEEDO_OBSERVATIONS: usize = 4;

/// The number of slots between logs that give detail about backfill process.
const BACKFILL_LOG_INTERVAL: u64 = 5;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network: Arc<NetworkGlobals<T::EthSpec>>,
    seconds_per_slot: u64,
) -> Result<(), String> {
    let slot_duration = Duration::from_secs(seconds_per_slot);

    let speedo = Mutex::new(Speedo::default());
    let log = executor.log().clone();

    // Keep track of sync state and reset the speedo on specific sync state changes.
    // Specifically, if we switch between a sync and a backfill sync, reset the speedo.
    let mut current_sync_state = network.sync_state();

    // Store info if we are required to do a backfill sync.
    let original_anchor_slot = beacon_chain
        .store
        .get_anchor_info()
        .map(|ai| ai.oldest_block_slot);

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
        let mut last_backfill_log_slot = None;

        loop {
            // Run the notifier half way through each slot.
            //
            // Keep remeasuring the offset rather than using an interval, so that we can correct
            // for system time clock adjustments.
            let wait = match beacon_chain.slot_clock.duration_to_next_slot() {
                Some(duration) => duration + slot_duration / 2,
                None => {
                    warn!(log, "Unable to read current slot");
                    sleep(slot_duration).await;
                    continue;
                }
            };
            sleep(wait).await;

            let connected_peer_count = network.connected_peers();
            let sync_state = network.sync_state();

            // Determine if we have switched syncing chains
            if sync_state != current_sync_state {
                match (current_sync_state, &sync_state) {
                    (_, SyncState::BackFillSyncing { .. }) => {
                        // We have transitioned to a backfill sync. Reset the speedo.
                        let mut speedo = speedo.lock().await;
                        speedo.clear();
                    }
                    (SyncState::BackFillSyncing { .. }, _) => {
                        // We have transitioned from a backfill sync, reset the speedo
                        let mut speedo = speedo.lock().await;
                        speedo.clear();
                    }
                    (_, _) => {}
                }
                current_sync_state = sync_state;
            }

            let cached_head = beacon_chain.canonical_head.cached_head();
            let head_slot = cached_head.head_slot();
            let head_root = cached_head.head_block_root();
            let finalized_checkpoint = cached_head.finalized_checkpoint();

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

            // The default is for regular sync but this gets modified if backfill sync is in
            // progress.
            let mut sync_distance = current_slot - head_slot;

            let mut speedo = speedo.lock().await;
            match current_sync_state {
                SyncState::BackFillSyncing { .. } => {
                    // Observe backfilling sync info.
                    if let Some(oldest_slot) = original_anchor_slot {
                        if let Some(current_anchor_slot) = beacon_chain
                            .store
                            .get_anchor_info()
                            .map(|ai| ai.oldest_block_slot)
                        {
                            sync_distance = current_anchor_slot;
                            speedo
                                // For backfill sync use a fake slot which is the distance we've progressed from the starting `oldest_block_slot`.
                                .observe(
                                    oldest_slot.saturating_sub(current_anchor_slot),
                                    Instant::now(),
                                );
                        }
                    }
                }
                SyncState::SyncingFinalized { .. }
                | SyncState::SyncingHead { .. }
                | SyncState::SyncTransition => {
                    speedo.observe(head_slot, Instant::now());
                }
                SyncState::Stalled | SyncState::Synced => {}
            }

            // NOTE: This is going to change based on which sync we are currently performing. A
            // backfill sync should process slots significantly faster than the other sync
            // processes.
            metrics::set_gauge(
                &metrics::SYNC_SLOTS_PER_SECOND,
                speedo.slots_per_second().unwrap_or(0_f64) as i64,
            );

            if connected_peer_count <= WARN_PEER_COUNT {
                warn!(log, "Low peer count"; "peer_count" => peer_count_pretty(connected_peer_count));
            }

            debug!(
                log,
                "Slot timer";
                "peers" => peer_count_pretty(connected_peer_count),
                "finalized_root" => format!("{}", finalized_checkpoint.root),
                "finalized_epoch" => finalized_checkpoint.epoch,
                "head_block" => format!("{}", head_root),
                "head_slot" => head_slot,
                "current_slot" => current_slot,
                "sync_state" =>format!("{}", current_sync_state)
            );

            // Log if we are backfilling.
            let is_backfilling = matches!(current_sync_state, SyncState::BackFillSyncing { .. });
            if is_backfilling
                && last_backfill_log_slot
                    .map_or(true, |slot| slot + BACKFILL_LOG_INTERVAL <= current_slot)
            {
                last_backfill_log_slot = Some(current_slot);

                let distance = format!(
                    "{} slots ({})",
                    sync_distance.as_u64(),
                    slot_distance_pretty(sync_distance, slot_duration)
                );

                let speed = speedo.slots_per_second();
                let display_speed = speed.map_or(false, |speed| speed != 0.0);

                if display_speed {
                    info!(
                        log,
                        "Downloading historical blocks";
                        "distance" => distance,
                        "speed" => sync_speed_pretty(speed),
                        "est_time" => estimated_time_pretty(speedo.estimated_time_till_slot(original_anchor_slot.unwrap_or(current_slot))),
                    );
                } else {
                    info!(
                        log,
                        "Downloading historical blocks";
                        "distance" => distance,
                        "est_time" => estimated_time_pretty(speedo.estimated_time_till_slot(original_anchor_slot.unwrap_or(current_slot))),
                    );
                }
            } else if !is_backfilling && last_backfill_log_slot.is_some() {
                last_backfill_log_slot = None;
                info!(
                    log,
                    "Historical block download complete";
                );
            }

            // Log if we are syncing
            if current_sync_state.is_syncing() {
                metrics::set_gauge(&metrics::IS_SYNCED, 0);
                let distance = format!(
                    "{} slots ({})",
                    sync_distance.as_u64(),
                    slot_distance_pretty(sync_distance, slot_duration)
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
            } else if current_sync_state.is_synced() {
                metrics::set_gauge(&metrics::IS_SYNCED, 1);
                let block_info = if current_slot > head_slot {
                    "   …  empty".to_string()
                } else {
                    head_root.to_string()
                };

                let block_hash = match beacon_chain.canonical_head.head_execution_status() {
                    Ok(ExecutionStatus::Irrelevant(_)) => "n/a".to_string(),
                    Ok(ExecutionStatus::Valid(hash)) => format!("{} (verified)", hash),
                    Ok(ExecutionStatus::Optimistic(hash)) => {
                        warn!(
                            log,
                            "Head is optimistic";
                            "info" => "chain not fully verified, \
                                block and attestation production disabled until execution engine syncs",
                            "execution_block_hash" => ?hash,
                        );
                        format!("{} (unverified)", hash)
                    }
                    Ok(ExecutionStatus::Invalid(hash)) => {
                        crit!(
                            log,
                            "Head execution payload is invalid";
                            "msg" => "this scenario may be unrecoverable",
                            "execution_block_hash" => ?hash,
                        );
                        format!("{} (invalid)", hash)
                    }
                    Err(_) => "unknown".to_string(),
                };

                info!(
                    log,
                    "Synced";
                    "peers" => peer_count_pretty(connected_peer_count),
                    "exec_hash" => block_hash,
                    "finalized_root" => format!("{}", finalized_checkpoint.root),
                    "finalized_epoch" => finalized_checkpoint.epoch,
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
                    "finalized_root" => format!("{}", finalized_checkpoint.root),
                    "finalized_epoch" => finalized_checkpoint.epoch,
                    "head_slot" => head_slot,
                    "current_slot" => current_slot,
                );
            }

            eth1_logging(&beacon_chain, &log);
            merge_readiness_logging(current_slot, &beacon_chain, &log).await;
            capella_readiness_logging(current_slot, &beacon_chain, &log).await;
        }
    };

    // run the notifier on the current executor
    executor.spawn(interval_future, "notifier");

    Ok(())
}

/// Provides some helpful logging to users to indicate if their node is ready for the Bellatrix
/// fork and subsequent merge transition.
async fn merge_readiness_logging<T: BeaconChainTypes>(
    current_slot: Slot,
    beacon_chain: &BeaconChain<T>,
    log: &Logger,
) {
    let merge_completed = beacon_chain
        .canonical_head
        .cached_head()
        .snapshot
        .beacon_block
        .message()
        .body()
        .execution_payload()
        .map_or(false, |payload| {
            payload.parent_hash() != ExecutionBlockHash::zero()
        });

    let has_execution_layer = beacon_chain.execution_layer.is_some();

    if merge_completed && has_execution_layer
        || !beacon_chain.is_time_to_prepare_for_bellatrix(current_slot)
    {
        return;
    }

    if merge_completed && !has_execution_layer {
        if !beacon_chain.is_time_to_prepare_for_capella(current_slot) {
            // logging of the EE being offline is handled in `capella_readiness_logging()`
            error!(
                log,
                "Execution endpoint required";
                "info" => "you need an execution engine to validate blocks, see: \
                           https://lighthouse-book.sigmaprime.io/merge-migration.html"
            );
        }
        return;
    }

    match beacon_chain.check_merge_readiness().await {
        MergeReadiness::Ready {
            config,
            current_difficulty,
        } => match config {
            MergeConfig {
                terminal_total_difficulty: Some(ttd),
                terminal_block_hash: None,
                terminal_block_hash_epoch: None,
            } => {
                info!(
                    log,
                    "Ready for the merge";
                    "terminal_total_difficulty" => %ttd,
                    "current_difficulty" => current_difficulty
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "??".into()),
                )
            }
            MergeConfig {
                terminal_total_difficulty: _,
                terminal_block_hash: Some(terminal_block_hash),
                terminal_block_hash_epoch: Some(terminal_block_hash_epoch),
            } => {
                info!(
                    log,
                    "Ready for the merge";
                    "info" => "you are using override parameters, please ensure that you \
                        understand these parameters and their implications.",
                    "terminal_block_hash" => ?terminal_block_hash,
                    "terminal_block_hash_epoch" => ?terminal_block_hash_epoch,
                )
            }
            other => error!(
                log,
                "Inconsistent merge configuration";
                "config" => ?other
            ),
        },
        readiness @ MergeReadiness::ExchangeTransitionConfigurationFailed { error: _ } => {
            error!(
                log,
                "Not ready for merge";
                "info" => %readiness,
                "hint" => "try updating Lighthouse and/or the execution layer",
            )
        }
        readiness @ MergeReadiness::NotSynced => warn!(
            log,
            "Not ready for merge";
            "info" => %readiness,
        ),
        readiness @ MergeReadiness::NoExecutionEndpoint => warn!(
            log,
            "Not ready for merge";
            "info" => %readiness,
        ),
    }
}

/// Provides some helpful logging to users to indicate if their node is ready for Capella
async fn capella_readiness_logging<T: BeaconChainTypes>(
    current_slot: Slot,
    beacon_chain: &BeaconChain<T>,
    log: &Logger,
) {
    let capella_completed = beacon_chain
        .canonical_head
        .cached_head()
        .snapshot
        .beacon_block
        .message()
        .body()
        .execution_payload()
        .map_or(false, |payload| payload.withdrawals_root().is_ok());

    let has_execution_layer = beacon_chain.execution_layer.is_some();

    if capella_completed && has_execution_layer
        || !beacon_chain.is_time_to_prepare_for_capella(current_slot)
    {
        return;
    }

    if capella_completed && !has_execution_layer {
        error!(
            log,
            "Execution endpoint required";
            "info" => "you need a Capella enabled execution engine to validate blocks, see: \
                       https://lighthouse-book.sigmaprime.io/merge-migration.html"
        );
        return;
    }

    match beacon_chain.check_capella_readiness().await {
        CapellaReadiness::Ready => {
            info!(log, "Ready for Capella")
        }
        readiness @ CapellaReadiness::ExchangeCapabilitiesFailed { error: _ } => {
            error!(
                log,
                "Not ready for Capella";
                "info" => %readiness,
                "hint" => "try updating Lighthouse and/or the execution layer",
            )
        }
        readiness => warn!(
            log,
            "Not ready for Capella";
            "info" => %readiness,
        ),
    }
}

fn eth1_logging<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>, log: &Logger) {
    let current_slot_opt = beacon_chain.slot().ok();

    // Perform some logging about the eth1 chain
    if let Some(eth1_chain) = beacon_chain.eth1_chain.as_ref() {
        // No need to do logging if using the dummy backend.
        if eth1_chain.is_dummy_backend() {
            return;
        }

        if let Some(status) = eth1_chain.sync_status(
            beacon_chain.genesis_time,
            current_slot_opt,
            &beacon_chain.spec,
        ) {
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
                    "Syncing deposit contract block cache";
                    "est_blocks_remaining" => distance,
                );
            }
        } else {
            error!(
                log,
                "Unable to determine deposit contract sync status";
            );
        }
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

    /// Clears all past observations to be used for an alternative sync (i.e backfill sync).
    pub fn clear(&mut self) {
        self.0.clear()
    }
}
