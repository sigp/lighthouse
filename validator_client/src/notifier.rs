use crate::{DutiesService, ProductionValidatorClient};
use metrics::set_gauge;
use slog::{debug, error, info, Logger};
use slot_clock::SlotClock;
use tokio::time::{sleep, Duration};
use types::EthSpec;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<E: EthSpec>(client: &ProductionValidatorClient<E>) -> Result<(), String> {
    let context = client.context.service_context("notifier".into());
    let executor = context.executor.clone();
    let duties_service = client.duties_service.clone();

    let slot_duration = Duration::from_secs(context.eth2_config.spec.seconds_per_slot);

    let interval_fut = async move {
        let log = context.log();

        loop {
            if let Some(duration_to_next_slot) = duties_service.slot_clock.duration_to_next_slot() {
                sleep(duration_to_next_slot + slot_duration / 2).await;
                notify(&duties_service, log).await;
            } else {
                error!(log, "Failed to read slot clock");
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
async fn notify<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
    log: &Logger,
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
            log,
            "Connected to beacon node(s)";
            "primary" => primary,
            "total" => num_total,
            "available" => num_available,
            "synced" => num_synced,
        )
    } else {
        error!(
            log,
            "No synced beacon nodes";
            "total" => num_total,
            "available" => num_available,
            "synced" => num_synced,
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
                log,
                "Beacon node info";
                "status" => "Connected",
                "index" => info.index,
                "endpoint" => info.endpoint,
                "head_slot" => %health.head,
                "is_optimistic" => ?health.optimistic_status,
                "execution_engine_status" => ?health.execution_status,
                "health_tier" => %health.health_tier,
            );
        } else {
            debug!(
                log,
                "Beacon node info";
                "status" => "Disconnected",
                "index" => info.index,
                "endpoint" => info.endpoint,
            );
        }
    }

    if let Some(slot) = duties_service.slot_clock.now() {
        let epoch = slot.epoch(E::slots_per_epoch());

        let total_validators = duties_service.total_validator_count();
        let proposing_validators = duties_service.proposer_count(epoch);
        let attesting_validators = duties_service.attester_count(epoch);
        let doppelganger_detecting_validators = duties_service.doppelganger_detecting_count();

        if doppelganger_detecting_validators > 0 {
            info!(log, "Listening for doppelgangers"; "doppelganger_detecting_validators" => doppelganger_detecting_validators)
        }

        if total_validators == 0 {
            info!(
                log,
                "No validators present";
                "msg" => "see `lighthouse vm create --help` or the HTTP API documentation"
            )
        } else if total_validators == attesting_validators {
            info!(
                log,
                "All validators active";
                "current_epoch_proposers" => proposing_validators,
                "active_validators" => attesting_validators,
                "total_validators" => total_validators,
                "epoch" => format!("{}", epoch),
                "slot" => format!("{}", slot),
            );
        } else if attesting_validators > 0 {
            info!(
                log,
                "Some validators active";
                "current_epoch_proposers" => proposing_validators,
                "active_validators" => attesting_validators,
                "total_validators" => total_validators,
                "epoch" => format!("{}", epoch),
                "slot" => format!("{}", slot),
            );
        } else {
            info!(
                log,
                "Awaiting activation";
                "validators" => total_validators,
                "epoch" => format!("{}", epoch),
                "slot" => format!("{}", slot),
            );
        }
    } else {
        error!(log, "Unable to read slot clock");
    }
}
