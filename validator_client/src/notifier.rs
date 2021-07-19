use crate::http_metrics;
use crate::{DutiesService, ProductionValidatorClient};
use lighthouse_metrics::set_gauge;
use slog::{error, info, Logger};
use slot_clock::SlotClock;
use tokio::time::{sleep, Duration};
use types::EthSpec;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: EthSpec>(client: &ProductionValidatorClient<T>) -> Result<(), String> {
    let context = client.context.service_context("notifier".into());
    let executor = context.executor.clone();
    let duties_service = client.duties_service.clone();

    let slot_duration = Duration::from_secs(context.eth2_config.spec.seconds_per_slot);

    let interval_fut = async move {
        let log = context.log();

        loop {
            if let Some(duration_to_next_slot) = duties_service.slot_clock.duration_to_next_slot() {
                sleep(duration_to_next_slot + slot_duration / 2).await;
                notify(&duties_service, &log).await;
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
    let num_available = duties_service.beacon_nodes.num_available().await;
    let num_synced = duties_service.beacon_nodes.num_synced().await;
    let num_total = duties_service.beacon_nodes.num_total();
    if num_synced > 0 {
        info!(
            log,
            "Connected to beacon node(s)";
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
    let num_synced_fallback = duties_service.beacon_nodes.num_synced_fallback().await;
    if num_synced_fallback > 0 {
        set_gauge(&http_metrics::metrics::ETH2_FALLBACK_CONNECTED, 1);
    } else {
        set_gauge(&http_metrics::metrics::ETH2_FALLBACK_CONNECTED, 0);
    }

    if let Some(slot) = duties_service.slot_clock.now() {
        let epoch = slot.epoch(E::slots_per_epoch());

        let total_validators = duties_service.total_validator_count();
        let proposing_validators = duties_service.proposer_count(epoch);
        let attesting_validators = duties_service.attester_count(epoch);

        if total_validators == 0 {
            info!(
                log,
                "No validators present";
                "msg" => "see `lighthouse account validator create --help` \
                or the HTTP API documentation"
            )
        } else if total_validators == attesting_validators {
            info!(
                log,
                "All validators active";
                "proposers" => proposing_validators,
                "active_validators" => attesting_validators,
                "total_validators" => total_validators,
                "epoch" => format!("{}", epoch),
                "slot" => format!("{}", slot),
            );
        } else if attesting_validators > 0 {
            info!(
                log,
                "Some validators active";
                "proposers" => proposing_validators,
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
