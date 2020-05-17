use crate::{is_synced::is_synced, ProductionValidatorClient};
use exit_future::Signal;
use futures::{FutureExt, StreamExt};
use slog::{error, info};
use slot_clock::SlotClock;
use tokio::time::{interval_at, Duration, Instant};
use types::EthSpec;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: EthSpec>(client: &ProductionValidatorClient<T>) -> Result<Signal, String> {
    let context = client.context.service_context("notifier".into());
    let runtime_handle = context.runtime_handle.clone();
    let log = context.log.clone();
    let duties_service = client.duties_service.clone();
    let allow_unsynced_beacon_node = client.config.allow_unsynced_beacon_node;

    let slot_duration = Duration::from_millis(context.eth2_config.spec.milliseconds_per_slot);
    let duration_to_next_slot = duties_service
        .slot_clock
        .duration_to_next_slot()
        .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Run the notifier half way through each slot.
    let start_instant = Instant::now() + duration_to_next_slot + (slot_duration / 2);
    let mut interval = interval_at(start_instant, slot_duration);

    let interval_fut = async move {
        let log = &context.log;

        while interval.next().await.is_some() {
            if !is_synced(
                &duties_service.beacon_node,
                &duties_service.slot_clock,
                Some(&log),
            )
            .await
                && !allow_unsynced_beacon_node
            {
                continue;
            }

            if let Some(slot) = duties_service.slot_clock.now() {
                let epoch = slot.epoch(T::slots_per_epoch());

                let total_validators = duties_service.total_validator_count();
                let proposing_validators = duties_service.proposer_count(epoch);
                let attesting_validators = duties_service.attester_count(epoch);

                if total_validators == 0 {
                    error!(log, "No validators present")
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

    let (exit_signal, exit) = exit_future::signal();
    let future = futures::future::select(
        Box::pin(interval_fut),
        exit.map(move |_| info!(log, "Shutdown complete")),
    );
    runtime_handle.spawn(future);

    Ok(exit_signal)
}
