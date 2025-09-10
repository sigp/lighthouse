use crate::duties_service::DutiesService;
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec};
use validator_metrics::set_gauge;
use validator_store::ValidatorStore;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<S: ValidatorStore + 'static, T: SlotClock + 'static>(
    duties_service: Arc<DutiesService<S, T>>,
    executor: TaskExecutor,
    spec: &ChainSpec,
) -> Result<(), String> {
    let slot_duration = Duration::from_secs(spec.seconds_per_slot);

    let interval_fut = async move {
        loop {
            if let Some(duration_to_next_slot) = duties_service.slot_clock.duration_to_next_slot() {
                sleep(duration_to_next_slot + slot_duration / 2).await;
                notify(&duties_service).await;
            } else {
                error!("Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
                continue;
            }
        }
    };

    executor.spawn(interval_fut, "validator_notifier");
    Ok(())
}

/// Performs a single notification routine.
pub async fn notify<S: ValidatorStore, T: SlotClock + 'static>(
    duties_service: &DutiesService<S, T>,
) {
    let (candidate_info, num_available, num_synced) =
        duties_service.beacon_nodes.get_notifier_info().await;
    let num_total = candidate_info.len();
    let num_synced_fallback = num_synced.saturating_sub(1);

    set_gauge(
        &validator_metrics::AVAILABLE_BEACON_NODES_COUNT,
        num_available as i64,
    );
    set_gauge(
        &validator_metrics::SYNCED_BEACON_NODES_COUNT,
        num_synced as i64,
    );
    set_gauge(
        &validator_metrics::TOTAL_BEACON_NODES_COUNT,
        num_total as i64,
    );
    if num_synced > 0 {
        let primary = candidate_info
            .first()
            .map(|candidate| candidate.endpoint.as_str())
            .unwrap_or("None");
        info!(
            primary,
            total = num_total,
            available = num_available,
            synced = num_synced,
            "Connected to beacon node(s)"
        )
    } else {
        error!(
            total = num_total,
            available = num_available,
            synced = num_synced,
            "No synced beacon nodes"
        )
    }
    if num_synced_fallback > 0 {
        set_gauge(&validator_metrics::ETH2_FALLBACK_CONNECTED, 1);
    } else {
        set_gauge(&validator_metrics::ETH2_FALLBACK_CONNECTED, 0);
    }

    for info in candidate_info {
        if let Ok(health) = info.health {
            debug!(
                status = "Connected",
                index = info.index,
                endpoint = info.endpoint,
                head_slot = %health.head,
                is_optimistic = ?health.optimistic_status,
                execution_engine_status = ?health.execution_status,
                health_tier = %health.health_tier,
                "Beacon node info"
            );
        } else {
            debug!(
                status = "Disconnected",
                index = info.index,
                endpoint = info.endpoint,
                "Beacon node info"
            );
        }
    }

    if let Some(slot) = duties_service.slot_clock.now() {
        let epoch = slot.epoch(S::E::slots_per_epoch());

        let total_validators = duties_service.total_validator_count();
        let proposing_validators = duties_service.proposer_count(epoch);
        let attesting_validators = duties_service.attester_count(epoch);
        let doppelganger_detecting_validators = duties_service.doppelganger_detecting_count();

        if doppelganger_detecting_validators > 0 {
            info!(
                doppelganger_detecting_validators,
                "Listening for doppelgangers"
            )
        }

        if total_validators == 0 {
            info!(
                msg = "see `lighthouse vm create --help` or the HTTP API documentation",
                "No validators present"
            )
        } else if total_validators == attesting_validators {
            info!(
                current_epoch_proposers = proposing_validators,
                active_validators = attesting_validators,
                total_validators = total_validators,
                %epoch,
                %slot,
                "All validators active"
            );
        } else if attesting_validators > 0 {
            info!(
                current_epoch_proposers = proposing_validators,
                active_validators = attesting_validators,
                total_validators = total_validators,
                %epoch,
                %slot,
                "Some validators active"
            );
        } else {
            info!(
                validators = total_validators,
                %epoch,
                %slot,
                "Awaiting activation"
            );
        }
    } else {
        error!("Unable to read slot clock");
    }
}
