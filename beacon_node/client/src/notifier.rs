use crate::metrics;
use beacon_chain::{
    BeaconChain, BeaconChainTypes, ExecutionStatus,
    bellatrix_readiness::{
        BellatrixReadiness, GenesisExecutionPayloadStatus, MergeConfig, SECONDS_IN_A_WEEK,
    },
};
use execution_layer::{
    EngineCapabilities,
    http::{
        ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_FORKCHOICE_UPDATED_V3, ENGINE_GET_PAYLOAD_V2,
        ENGINE_GET_PAYLOAD_V3, ENGINE_GET_PAYLOAD_V4, ENGINE_GET_PAYLOAD_V5, ENGINE_NEW_PAYLOAD_V2,
        ENGINE_NEW_PAYLOAD_V3, ENGINE_NEW_PAYLOAD_V4,
    },
};
use lighthouse_network::{NetworkGlobals, types::SyncState};
use logging::crit;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
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

pub const FORK_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network: Arc<NetworkGlobals<T::EthSpec>>,
    seconds_per_slot: u64,
) -> Result<(), String> {
    let slot_duration = Duration::from_secs(seconds_per_slot);

    let speedo = Mutex::new(Speedo::default());

    // Keep track of sync state and reset the speedo on specific sync state changes.
    // Specifically, if we switch between a sync and a backfill sync, reset the speedo.
    let mut current_sync_state = network.sync_state();

    // Store info if we are required to do a backfill sync.
    let original_oldest_block_slot = beacon_chain.store.get_anchor_info().oldest_block_slot;

    // Use this info during custody backfill sync.
    let mut original_earliest_data_column_slot = None;

    let interval_future = async move {
        // Perform pre-genesis logging.
        loop {
            match beacon_chain.slot_clock.duration_to_next_slot() {
                // If the duration to the next slot is greater than the slot duration, then we are
                // waiting for genesis.
                Some(next_slot) if next_slot > slot_duration => {
                    info!(
                        peers = peer_count_pretty(network.connected_peers()),
                        wait_time = estimated_time_pretty(Some(next_slot.as_secs() as f64)),
                        "Waiting for genesis"
                    );
                    bellatrix_readiness_logging(Slot::new(0), &beacon_chain).await;
                    post_bellatrix_readiness_logging(Slot::new(0), &beacon_chain).await;
                    genesis_execution_payload_logging(&beacon_chain).await;
                    sleep(slot_duration).await;
                }
                _ => break,
            }
        }

        // Perform post-genesis logging.
        let mut last_backfill_log_slot = None;
        let mut last_custody_backfill_log_slot = None;

        loop {
            // Run the notifier half way through each slot.
            //
            // Keep remeasuring the offset rather than using an interval, so that we can correct
            // for system time clock adjustments.
            let wait = match beacon_chain.slot_clock.duration_to_next_slot() {
                Some(duration) => duration + slot_duration / 2,
                None => {
                    warn!("Unable to read current slot");
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
                    (_, SyncState::CustodyBackFillSyncing { .. }) => {
                        // We have transitioned to a custody backfill sync. Reset the speedo.
                        let mut speedo = speedo.lock().await;
                        last_custody_backfill_log_slot = None;
                        speedo.clear();
                    }
                    (SyncState::CustodyBackFillSyncing { .. }, _) => {
                        // We have transitioned from a custody backfill sync, reset the speedo
                        let mut speedo = speedo.lock().await;
                        last_custody_backfill_log_slot = None;
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
                    error!(error = ?e, "Unable to read current slot");
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
                    let current_oldest_block_slot =
                        beacon_chain.store.get_anchor_info().oldest_block_slot;
                    sync_distance = current_oldest_block_slot
                        .saturating_sub(beacon_chain.genesis_backfill_slot);
                    speedo
                        // For backfill sync use a fake slot which is the distance we've progressed
                        // from the starting `original_oldest_block_slot`.
                        .observe(
                            original_oldest_block_slot.saturating_sub(current_oldest_block_slot),
                            Instant::now(),
                        );
                }
                SyncState::CustodyBackFillSyncing { .. } => {
                    match beacon_chain.store.get_data_column_custody_info() {
                        Ok(data_column_custody_info) => {
                            if let Some(earliest_data_column_slot) = data_column_custody_info
                                .and_then(|info| info.earliest_data_column_slot)
                                && let Some(da_boundary) = beacon_chain.get_column_da_boundary()
                            {
                                sync_distance = earliest_data_column_slot.saturating_sub(
                                    da_boundary.start_slot(T::EthSpec::slots_per_epoch()),
                                );

                                // We keep track of our starting point for custody backfill sync
                                // so we can measure our speed of progress.
                                if original_earliest_data_column_slot.is_none() {
                                    original_earliest_data_column_slot =
                                        Some(earliest_data_column_slot)
                                }

                                if let Some(original_earliest_data_column_slot) =
                                    original_earliest_data_column_slot
                                {
                                    speedo.observe(
                                        original_earliest_data_column_slot
                                            .saturating_sub(earliest_data_column_slot),
                                        Instant::now(),
                                    );
                                }
                            }
                        }
                        Err(e) => error!(error=?e, "Unable to get data column custody info"),
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
                warn!(
                    peer_count = peer_count_pretty(connected_peer_count),
                    "Low peer count"
                );
            }

            debug!(
                peers = peer_count_pretty(connected_peer_count),
                finalized_root = %finalized_checkpoint.root,
                finalized_epoch = %finalized_checkpoint.epoch,
                head_block = %head_root,
                %head_slot,
                %current_slot,
                sync_state = %current_sync_state,
                "Slot timer"
            );

            // Log if we are backfilling.
            let is_backfilling = matches!(current_sync_state, SyncState::BackFillSyncing { .. });
            let is_custody_backfilling =
                matches!(current_sync_state, SyncState::CustodyBackFillSyncing { .. });
            if is_backfilling
                && last_backfill_log_slot
                    .is_none_or(|slot| slot + BACKFILL_LOG_INTERVAL <= current_slot)
            {
                last_backfill_log_slot = Some(current_slot);

                let distance = format!(
                    "{} slots ({})",
                    sync_distance.as_u64(),
                    slot_distance_pretty(sync_distance, slot_duration)
                );

                let speed = speedo.slots_per_second();
                let display_speed = speed.is_some_and(|speed| speed != 0.0);

                if display_speed {
                    info!(
                        distance,
                        speed = sync_speed_pretty(speed),
                        est_time = estimated_time_pretty(
                            speedo.estimated_time_till_slot(
                                original_oldest_block_slot
                                    .saturating_sub(beacon_chain.genesis_backfill_slot)
                            )
                        ),
                        "Downloading historical blocks"
                    );
                } else {
                    info!(
                        distance,
                        est_time = estimated_time_pretty(
                            speedo.estimated_time_till_slot(
                                original_oldest_block_slot
                                    .saturating_sub(beacon_chain.genesis_backfill_slot)
                            )
                        ),
                        "Downloading historical blocks"
                    );
                }
            } else if !is_backfilling && last_backfill_log_slot.is_some() {
                last_backfill_log_slot = None;
                info!("Historical block download complete");
            }

            if is_custody_backfilling
                && last_custody_backfill_log_slot
                    .is_none_or(|slot| slot + BACKFILL_LOG_INTERVAL <= current_slot)
            {
                last_custody_backfill_log_slot = Some(current_slot);

                let distance = format!(
                    "{} slots ({})",
                    sync_distance.as_u64(),
                    slot_distance_pretty(sync_distance, slot_duration)
                );

                let speed = speedo.slots_per_second();
                let display_speed = speed.is_some_and(|speed| speed != 0.0);
                let est_time_in_secs = if let (Some(da_boundary_epoch), Some(original_slot)) = (
                    beacon_chain.get_column_da_boundary(),
                    original_earliest_data_column_slot,
                ) {
                    let target = original_slot.saturating_sub(
                        da_boundary_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                    );
                    speedo.estimated_time_till_slot(target)
                } else {
                    None
                };
                if display_speed {
                    info!(
                        distance,
                        speed = sync_speed_pretty(speed),
                        est_time = estimated_time_pretty(est_time_in_secs),
                        "Downloading historical data columns"
                    );
                } else {
                    info!(
                        distance,
                        est_time = estimated_time_pretty(est_time_in_secs),
                        "Downloading historical data columns"
                    );
                }
            } else if !is_custody_backfilling && last_custody_backfill_log_slot.is_some() {
                last_custody_backfill_log_slot = None;
                original_earliest_data_column_slot = None;
                info!("Historical data column download complete");
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
                let display_speed = speed.is_some_and(|speed| speed != 0.0);

                if display_speed {
                    info!(
                        peers = peer_count_pretty(connected_peer_count),
                        distance,
                        speed = sync_speed_pretty(speed),
                        est_time =
                            estimated_time_pretty(speedo.estimated_time_till_slot(current_slot)),
                        "Syncing"
                    );
                } else {
                    info!(
                        peers = peer_count_pretty(connected_peer_count),
                        distance,
                        est_time =
                            estimated_time_pretty(speedo.estimated_time_till_slot(current_slot)),
                        "Syncing"
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
                            info = "chain not fully verified, \
                            block and attestation production disabled until execution engine syncs",
                        execution_block_hash = ?hash,
                            "Head is optimistic"
                        );
                        format!("{} (unverified)", hash)
                    }
                    Ok(ExecutionStatus::Invalid(hash)) => {
                        crit!(
                            msg = "this scenario may be unrecoverable",
                            execution_block_hash = ?hash,
                            "Head execution payload is invalid"
                        );
                        format!("{} (invalid)", hash)
                    }
                    Err(_) => "unknown".to_string(),
                };

                info!(
                    peers = peer_count_pretty(connected_peer_count),
                    exec_hash = block_hash,
                    finalized_root = %finalized_checkpoint.root,
                    finalized_epoch = %finalized_checkpoint.epoch,
                    epoch = %current_epoch,
                    block = block_info,
                    slot = %current_slot,
                    "Synced"
                );
            } else {
                metrics::set_gauge(&metrics::IS_SYNCED, 0);
                info!(
                    peers = peer_count_pretty(connected_peer_count),
                    finalized_root = %finalized_checkpoint.root,
                    finalized_epoch = %finalized_checkpoint.epoch,
                    %head_slot,
                    %current_slot,
                    "Searching for peers"
                );
            }

            bellatrix_readiness_logging(current_slot, &beacon_chain).await;
            post_bellatrix_readiness_logging(current_slot, &beacon_chain).await;
        }
    };

    // run the notifier on the current executor
    executor.spawn(interval_future, "notifier");

    Ok(())
}

/// Provides some helpful logging to users to indicate if their node is ready for the Bellatrix
/// fork and subsequent merge transition.
async fn bellatrix_readiness_logging<T: BeaconChainTypes>(
    current_slot: Slot,
    beacon_chain: &BeaconChain<T>,
) {
    let merge_completed = beacon_chain
        .canonical_head
        .cached_head()
        .snapshot
        .beacon_block
        .message()
        .body()
        .execution_payload()
        .is_ok_and(|payload| payload.parent_hash() != ExecutionBlockHash::zero());

    let has_execution_layer = beacon_chain.execution_layer.is_some();

    if merge_completed && has_execution_layer
        || !beacon_chain.is_time_to_prepare_for_bellatrix(current_slot)
    {
        return;
    }

    match beacon_chain.check_bellatrix_readiness(current_slot).await {
        BellatrixReadiness::Ready {
            config,
            current_difficulty,
        } => match config {
            MergeConfig {
                terminal_total_difficulty: Some(ttd),
                terminal_block_hash: None,
                terminal_block_hash_epoch: None,
            } => {
                info!(
                    terminal_total_difficulty = %ttd,
                    current_difficulty = current_difficulty
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "??".into()),
                    "Ready for Bellatrix"
                )
            }
            MergeConfig {
                terminal_total_difficulty: _,
                terminal_block_hash: Some(terminal_block_hash),
                terminal_block_hash_epoch: Some(terminal_block_hash_epoch),
            } => {
                info!(
                    info = "you are using override parameters, please ensure that you \
                    understand these parameters and their implications.",
                    ?terminal_block_hash,
                    ?terminal_block_hash_epoch,
                    "Ready for Bellatrix"
                )
            }
            other => error!(
                config = ?other,
                "Inconsistent merge configuration"
            ),
        },
        readiness @ BellatrixReadiness::NotSynced => warn!(
            info = %readiness,
            "Not ready Bellatrix"
        ),
        readiness @ BellatrixReadiness::NoExecutionEndpoint => warn!(
            info = %readiness,
            "Not ready for Bellatrix"
        ),
    }
}

/// Provides some helpful logging to users to indicate if their node is ready for Capella
async fn post_bellatrix_readiness_logging<T: BeaconChainTypes>(
    current_slot: Slot,
    beacon_chain: &BeaconChain<T>,
) {
    if let Some(fork) = find_next_fork_to_prepare(current_slot, beacon_chain) {
        let readiness = if let Some(el) = beacon_chain.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => Err(format!("Exchange capabilities failed: {e:?}")),
                Ok(capabilities) => {
                    let missing_methods = methods_required_for_fork(fork, capabilities);
                    if missing_methods.is_empty() {
                        Ok(())
                    } else {
                        Err(format!("Missing required methods: {missing_methods:?}"))
                    }
                }
            }
        } else {
            Err("No execution endpoint".to_string())
        };

        if let Err(readiness) = readiness {
            warn!(
                info = %readiness,
                "Not ready for {}", fork
            );
        } else {
            info!(
                info = "ensure the execution endpoint is updated to the latest release",
                "Ready for {}", fork
            )
        }
    }
}

fn find_next_fork_to_prepare<T: BeaconChainTypes>(
    current_slot: Slot,
    beacon_chain: &BeaconChain<T>,
) -> Option<ForkName> {
    let head_fork = beacon_chain
        .canonical_head
        .cached_head()
        .snapshot
        .beacon_state
        .fork_name_unchecked();

    // Iterate forks from latest to oldest
    for (fork, fork_epoch) in ForkName::list_all_fork_epochs(&beacon_chain.spec)
        .iter()
        .rev()
    {
        // This readiness only handles capella and post fork
        if *fork <= ForkName::Bellatrix {
            break;
        }

        // head state has already activated this fork
        if head_fork >= *fork {
            break;
        }

        // Find the first fork that is scheduled and close to happen
        if let Some(fork_epoch) = fork_epoch {
            let fork_slot = fork_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let preparation_slots =
                FORK_READINESS_PREPARATION_SECONDS / beacon_chain.spec.seconds_per_slot;
            let in_fork_preparation_period = current_slot + preparation_slots > fork_slot;
            if in_fork_preparation_period {
                return Some(*fork);
            }
        }
    }

    None
}

fn methods_required_for_fork(
    fork: ForkName,
    capabilities: EngineCapabilities,
) -> Vec<&'static str> {
    let mut missing_methods = vec![];
    match fork {
        ForkName::Base | ForkName::Altair | ForkName::Bellatrix => {
            warn!(
                fork = %fork,
                "Invalid methods_required_for_fork call"
            );
        }
        ForkName::Capella => {
            if !capabilities.get_payload_v2 {
                missing_methods.push(ENGINE_GET_PAYLOAD_V2);
            }
            if !capabilities.forkchoice_updated_v2 {
                missing_methods.push(ENGINE_FORKCHOICE_UPDATED_V2);
            }
            if !capabilities.new_payload_v2 {
                missing_methods.push(ENGINE_NEW_PAYLOAD_V2);
            }
        }
        ForkName::Deneb => {
            if !capabilities.get_payload_v3 {
                missing_methods.push(ENGINE_GET_PAYLOAD_V3);
            }
            if !capabilities.forkchoice_updated_v3 {
                missing_methods.push(ENGINE_FORKCHOICE_UPDATED_V3);
            }
            if !capabilities.new_payload_v3 {
                missing_methods.push(ENGINE_NEW_PAYLOAD_V3);
            }
        }
        ForkName::Electra => {
            if !capabilities.get_payload_v4 {
                missing_methods.push(ENGINE_GET_PAYLOAD_V4);
            }
            if !capabilities.new_payload_v4 {
                missing_methods.push(ENGINE_NEW_PAYLOAD_V4);
            }
        }
        ForkName::Fulu => {
            if !capabilities.get_payload_v5 {
                missing_methods.push(ENGINE_GET_PAYLOAD_V5);
            }
            if !capabilities.new_payload_v4 {
                missing_methods.push(ENGINE_NEW_PAYLOAD_V4);
            }
        }
        ForkName::Gloas => {
            if !capabilities.get_payload_v5 {
                missing_methods.push(ENGINE_GET_PAYLOAD_V5);
            }
            if !capabilities.new_payload_v4 {
                missing_methods.push(ENGINE_NEW_PAYLOAD_V4);
            }
        }
    }
    missing_methods
}

async fn genesis_execution_payload_logging<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) {
    match beacon_chain
        .check_genesis_execution_payload_is_correct()
        .await
    {
        Ok(GenesisExecutionPayloadStatus::Correct(block_hash)) => {
            info!(
                genesis_payload_block_hash = ?block_hash,
                "Execution enabled from genesis"
            );
        }
        Ok(GenesisExecutionPayloadStatus::BlockHashMismatch { got, expected }) => {
            error!(
                info = "genesis is misconfigured and likely to fail",
                consensus_node_block_hash = ?expected,
                execution_node_block_hash = ?got,
                "Genesis payload block hash mismatch"
            );
        }
        Ok(GenesisExecutionPayloadStatus::TransactionsRootMismatch { got, expected }) => {
            error!(
                info = "genesis is misconfigured and likely to fail",
                consensus_node_transactions_root = ?expected,
                execution_node_transactions_root = ?got,
                "Genesis payload transactions root mismatch"
            );
        }
        Ok(GenesisExecutionPayloadStatus::WithdrawalsRootMismatch { got, expected }) => {
            error!(
                info = "genesis is misconfigured and likely to fail",
                consensus_node_withdrawals_root = ?expected,
                execution_node_withdrawals_root = ?got,
                "Genesis payload withdrawals root mismatch"
            );
        }
        Ok(GenesisExecutionPayloadStatus::OtherMismatch) => {
            error!(
                info = "genesis is misconfigured and likely to fail",
                detail = "see debug logs for payload headers",
                "Genesis payload header mismatch"
            );
        }
        Ok(GenesisExecutionPayloadStatus::Irrelevant) => {
            info!("Execution is not enabled from genesis");
        }
        Ok(GenesisExecutionPayloadStatus::AlreadyHappened) => {
            warn!(
                info = "this is probably a race condition or a bug",
                "Unable to check genesis which has already occurred"
            );
        }
        Err(e) => {
            error!(
                error = ?e,
                "Unable to check genesis execution payload"
            );
        }
    }
}

/// Returns the peer count, returning something helpful if it's `usize::MAX` (effectively a
/// `None` value).
fn peer_count_pretty(peer_count: usize) -> String {
    if peer_count == usize::MAX {
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
    /// Does not gracefully handle slots that are above `u32::MAX`.
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
