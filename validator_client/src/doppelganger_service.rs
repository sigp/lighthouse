use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use slog::{crit, error, info};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::ShutdownReason;
use tokio::time::sleep;
use types::{Epoch, EthSpec};

#[derive(Clone)]
pub struct DoppelgangerService<T: SlotClock, E: EthSpec> {
    pub slot_clock: T,
    pub validator_store: ValidatorStore<T, E>,
    pub beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    pub context: RuntimeContext<E>,
}

impl<T: 'static + SlotClock, E: EthSpec> DoppelgangerService<T, E> {
    pub fn start_update_service(self) -> Result<(), String> {
        let log = self.context.log().clone();

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            log,
            "Doppelganger detection service started";
            "next_update" => ?duration_to_next_slot
        );

        let current_epoch = self
            .slot_clock
            .now_or_genesis()
            .ok_or("Unable to read slot")?
            .epoch(E::slots_per_epoch());
        let genesis_epoch = self.slot_clock.genesis_slot().epoch(E::slots_per_epoch());

        self.validator_store
            .initialized_validators()
            .write()
            .update_all_initialization_epochs(current_epoch, genesis_epoch);

        let doppelganger_service = self.clone();
        self.context.executor.spawn(
            async move {
                loop {
                    if let Some(duration) = doppelganger_service.slot_clock.duration_to_next_slot()
                    {
                        sleep(duration).await;
                    } else {
                        // Just sleep for one slot if we are unable to read the system clock, this gives
                        // us an opportunity for the clock to eventually come good.
                        sleep(doppelganger_service.slot_clock.slot_duration()).await;
                        continue;
                    }

                    if let Err(e) = doppelganger_service.detect_doppelgangers().await {
                        error!(log,"Error during doppelganger detection"; "error" => ?e);
                    }
                }
            },
            "doppelganger_service",
        );
        Ok(())
    }

    async fn detect_doppelgangers(&self) -> Result<(), String> {
        let log = self.context.log().clone();

        let slot = self.slot_clock.now().ok_or("Unable to read slot clock")?;
        let epoch = slot.epoch(E::slots_per_epoch());

        // Get all validators requiring a doppelganger detection check.
        let validators_by_epoch = self
            .validator_store
            .initialized_validators()
            .read()
            .get_doppelganger_detecting_validators(epoch);

        // Avoid any unnecessary processing.
        if validators_by_epoch.is_empty() {
            return Ok(());
        }

        for (epoch, vals) in validators_by_epoch.iter() {
            // Ensure we don't send empty requests.
            if vals.is_empty() {
                break;
            }

            info!(log, "Monitoring for doppelgangers"; "epoch" => ?epoch);

            let vals_slice = vals.as_slice();
            let liveness_response = self
                .beacon_nodes
                .first_success(RequireSynced::Yes, |beacon_node| async move {
                    beacon_node
                        .post_lighthouse_liveness(vals_slice, *epoch)
                        .await
                        .map_err(|e| format!("Failed query for validator liveness: {:?}", e))
                        .map(|result| result.data)
                })
                .await
                .map_err(|e| format!("Failed query for validator liveness: {}", e));

            // Send a shutdown signal if necessary.
            match liveness_response {
                Ok(validator_liveness) => {
                    for validator in validator_liveness {
                        if validator.is_live {
                            crit!(
                                log,
                                "Doppelganger detected! Shutting down. Ensure you aren't already \
                                             running a validator client with the same keys.";
                                             "validator" => ?validator
                            );

                            let _ = self
                                .context
                                .executor
                                .shutdown_sender()
                                .try_send(ShutdownReason::Failure("Doppelganger detected."))
                                .map_err(|e| format!("Could not send shutdown signal: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    crit!(
                        log,
                        "Failed to complete query for doppelganger detection... Restarting doppelganger detection process.";
                        "error" => format!("{:?}", e)
                    );

                    let current_epoch = self
                        .slot_clock
                        .now_or_genesis()
                        .ok_or("Unable to read slot")?
                        .epoch(E::slots_per_epoch());
                    let genesis_epoch = self.slot_clock.genesis_slot().epoch(E::slots_per_epoch());

                    self.validator_store
                        .initialized_validators()
                        .write()
                        .update_all_initialization_epochs(current_epoch, genesis_epoch);
                }
            };
        }

        // If we are in the first slot of epoch N, consider checks in epoch N-1 completed.
        if slot == epoch.start_slot(E::slots_per_epoch()) {
            self.validator_store
                .initialized_validators()
                .write()
                .complete_doppelganger_detection_in_epoch(epoch.saturating_sub(Epoch::new(1)));
        }
        Ok(())
    }
}
