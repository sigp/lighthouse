use crate::ProductionValidatorClient;
use slog::{error, info};
use slot_clock::SlotClock;
use tokio::time::{interval_at, Duration, Instant};
use types::EthSpec;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: EthSpec>(client: &ProductionValidatorClient<T>) -> Result<(), String> {
    let context = client.context.service_context("notifier".into());
    let executor = context.executor.clone();
    let duties_service = client.duties_service.clone();

    let slot_duration = Duration::from_secs(context.eth2_config.spec.seconds_per_slot);
    let duration_to_next_slot = duties_service
        .slot_clock
        .duration_to_next_slot()
        .ok_or("slot_notifier unable to determine time to next slot")?;

    // Run the notifier half way through each slot.
    let start_instant = Instant::now() + duration_to_next_slot + (slot_duration / 2);
    let mut interval = interval_at(start_instant, slot_duration);

    let interval_fut = async move {
        let log = context.log();

        loop {
            interval.tick().await;
            let num_available = duties_service.beacon_nodes.num_available().await;
            let num_synced = duties_service.beacon_nodes.num_synced().await;
            let num_total = duties_service.beacon_nodes.num_total().await;
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

            if let Some(slot) = duties_service.slot_clock.now() {
                let epoch = slot.epoch(T::slots_per_epoch());

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
    };

    executor.spawn(interval_fut, "validator_notifier");
    Ok(())
}
