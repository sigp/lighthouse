use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use slog::{crit, info, trace, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::time::{interval_at, Duration, Instant};
use types::{ChainSpec, Epoch, EthSpec};
use crate::initialized_validators::DOPPELGANGER_DETECTION_EPOCHS;
use futures::channel::mpsc::Sender;
use futures::SinkExt;

#[derive(Clone)]
pub struct DoppelgangerService<T: SlotClock, E: EthSpec> {
    pub slot_clock: T,
    pub validator_store: ValidatorStore<T, E>,
    pub beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    pub context: RuntimeContext<E>,
    pub shutdown_sender: Sender<&'static str>,
}

impl<T: 'static + SlotClock, E: EthSpec> DoppelgangerService<T, E> {
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<(), String> {
        let log = self.context.log().clone();

        let slot_duration = Duration::from_secs(spec.seconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or("Unable to determine duration to next slot")?;

        info!(
            log,
            "Doppelganger detection service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
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
            .update_all_doppelganger_detection_epochs(current_epoch, genesis_epoch);

        let mut interval = {
            // Note: `interval_at` panics if `slot_duration` is 0
            interval_at(Instant::now() + duration_to_next_slot, slot_duration)
        };

        let executor = self.context.executor.clone();
        let mut shutdown_sender = executor.shutdown_sender();

        let interval_fut = async move {
            loop {
                interval.tick().await;
                let log = self.context.log();

                if let Err(e) = self.detect_doppelgangers().await {
                    let _ = shutdown_sender
                        .try_send("Doppelganger detected.").map_err(|e| format!("Could not send shutdown signal: {}", e)).unwrap();
                    break;
                } else {
                    trace!(
                        log,
                        "Spawned doppelganger detection tasks";
                    );
                }
            }
        };

        executor.spawn(interval_fut, "doppelganger_service");
        Ok(())
    }

    async fn detect_doppelgangers(&self) -> Result<(), String> {
        let log = self.context.log().clone();

        let slot = self.slot_clock.now().ok_or("Unable to read slot clock")?;
        let epoch = slot.epoch(E::slots_per_epoch());

        // get all validators in the doppelganger detection epoch
        let validator_map = self
            .validator_store
            .initialized_validators()
            .read()
            .get_doppelganger_detecting_validators_by_epoch(epoch);

        for (detection_epoch, validators) in validator_map {

            // This is to make sure we always check for attestations at the doppelganger detection epoch
            // and all epochs after the current epoch. We want to avoid the current epoch so we don't
            // pick up attestations from our own validator on restart.
            let epochs: Vec<Epoch> = (((detection_epoch - Epoch::new(DOPPELGANGER_DETECTION_EPOCHS)).as_u64() + 1)..=detection_epoch.as_u64()).map(Epoch::new).collect();

            let epochs_slice = epochs.as_slice();
            let validators_slice = validators.as_slice();
            info!(log, "Monitoring for doppelgangers"; "epochs" => ?epochs, "validators" => ?validators);

            let doppelganger_detected = self
                .beacon_nodes
                .first_success(RequireSynced::Yes, |beacon_node| async move {
                    beacon_node
                        .get_lighthouse_seen_validators(validators_slice, epochs_slice)
                        .await
                        .map_err(|e| format!("Failed query for seen validators: {:?}", e))
                        .map(|result| result.data)
                })
                .await
                .map_err(|e| format!("Failed query for seen validators: {}", e));

            // Send shutdown signal if necessary
            match doppelganger_detected {
                Ok(doppelgangers) => {
                    if !doppelgangers.is_empty() {
                        crit!(
                            log,
                            "Doppelganger detected! Shutting down. Ensure you aren't already \
                                         running a validator client with the same keys.";
                                         "doppelganger_indices" => ?doppelgangers
                        );

                        let _ = self
                            .shutdown_sender.clone()
                            .try_send("Doppelganger detected.").map_err(|e| format!("Could not send shutdown signal: {}", e))?;
                        return Err(format!("Doppelganger detected: {:?}", doppelgangers))
                    }
                }
                Err(e) => {
                    warn!(
                        log,
                        "Failed complete query for doppelganger detection... Restarting doppelganger detection process.";
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
                        .update_all_doppelganger_detection_epochs(current_epoch, genesis_epoch);
                }
            }
        }
        Ok(())
    }
}
