use crate::ProductionValidatorClient;
use exit_future::Signal;
use futures::{FutureExt, StreamExt};
use slog::{error, info};
use slot_clock::SlotClock;
use tokio::time::{interval_at, Duration, Instant};
use types::EthSpec;

/// Spawns a notifier service which periodically logs information about the node.
pub fn spawn_notifier<T: EthSpec>(client: &ProductionValidatorClient<T>) -> Result<Signal, String> {
    let context = client.context.service_context("notifier".into());

    let slot_duration = Duration::from_millis(context.eth2_config.spec.milliseconds_per_slot);
    let duration_to_next_slot = client
        .duties_service
        .slot_clock
        .duration_to_next_slot()
        .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

    // Run this half way through each slot.
    let start_instant = Instant::now() + duration_to_next_slot + (slot_duration / 2);

    // Run this each slot.
    let interval_duration = slot_duration;

    let duties_service = client.duties_service.clone();
    let log_1 = context.log.clone();

    // Note: interval_at panics if `interval_duration` is 0
    let interval_fut = interval_at(start_instant, interval_duration).for_each(move |_| {
        let log = log_1.clone();

        if let Some(slot) = duties_service.slot_clock.now() {
            let epoch = slot.epoch(T::slots_per_epoch());

            let total_validators = duties_service.total_validator_count();
            let proposing_validators = duties_service.proposer_count(epoch);
            let attesting_validators = duties_service.attester_count(epoch);

            if total_validators == 0 {
                error!(log, "No validators present")
            } else if total_validators == attesting_validators {
                info!(
                    log_1,
                    "All validators active";
                    "proposers" => proposing_validators,
                    "active_validators" => attesting_validators,
                    "total_validators" => total_validators,
                    "epoch" => format!("{}", epoch),
                    "slot" => format!("{}", slot),
                );
            } else if attesting_validators > 0 {
                info!(
                    log_1,
                    "Some validators active";
                    "proposers" => proposing_validators,
                    "active_validators" => attesting_validators,
                    "total_validators" => total_validators,
                    "epoch" => format!("{}", epoch),
                    "slot" => format!("{}", slot),
                );
            } else {
                info!(
                    log_1,
                    "Awaiting activation";
                    "validators" => total_validators,
                    "epoch" => format!("{}", epoch),
                    "slot" => format!("{}", slot),
                );
            }
        } else {
            error!(log, "Unable to read slot clock");
        }

        futures::future::ready(())
    });

    let (exit_signal, exit) = exit_future::signal();
    let log = context.log.clone();
    let future = futures::future::select(
        interval_fut,
        exit.map(move |_| info!(log, "Shutdown complete")),
    );
    tokio::task::spawn(future);

    Ok(exit_signal)
}
