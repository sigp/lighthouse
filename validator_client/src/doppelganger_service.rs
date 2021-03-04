use environment::RuntimeContext;
use slot_clock::SlotClock;
use types::{ChainSpec, EthSpec};
use tokio::time::{interval_at, sleep_until, Duration, Instant};
use crate::validator_store::ValidatorStore;

pub struct DoppelgangerService<T,E> {
    slot_clock: Option<T>,
    validator_store: ValidatorStore<T, E>,
    context: RuntimeContext<E>,
}

impl <T: SlotClock, E: EthSpec> DoppelgangerService<T,E> {
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<(), String> {
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

        let mut interval = {
            // Note: `interval_at` panics if `slot_duration` is 0
            interval_at(
                Instant::now() + duration_to_next_slot,
                slot_duration,
            )
        };

        let executor = self.context.executor.clone();

        let interval_fut = async move {
            loop {
                interval.tick().await;
                let log = self.context.log();

                if let Err(e) = self.do_update(slot_duration) {
                    crit!(
                        log,
                        "Failed to spawn attestation tasks";
                        "error" => e
                    )
                } else {
                    trace!(
                        log,
                        "Spawned attestation tasks";
                    )
                }
            }
        };

        executor.spawn(interval_fut, "attestation_service");
        Ok(())
    }

    fn do_update(&self, slot_duration: Duration) -> Result<(), String> {


        // Check for doppelgangers if configured
         if let Some(slot) = self.slot_clock.now() {
             let epoch = slot.epoch(E::slots_per_epoch());

             let validators  = self.validator_store.initialized_validators().read().get_all_doppelganger_detecting_validators()?;

             // get all validators in the doppelganger detection epoch

             if doppelganger_epoch >= epoch {
                 info!(log, "Monitoring for doppelgangers"; "epoch" => epoch, "slot" => slot, "doppelganger_detection_epoch" => doppelganger_epoch);

                 let mut epochs =
                     Vec::with_capacity(DOPPELGANGER_DETECTION_EPOCHS as usize);
                 for i in 0..DOPPELGANGER_DETECTION_EPOCHS - 1 {
                     epochs.push(doppelganger_epoch - Epoch::new(i));
                 }
                 let epochs_slice = epochs.as_slice();

                 let pubkeys = self.validator_store.voting_pubkeys();
                 let pubkeys_slice = pubkeys.as_slice();

                 let doppelganger_detected = self
                     .beacon_nodes
                     .first_success(RequireSynced::Yes, |beacon_node| async move {
                         beacon_node
                             .get_lighthouse_seen_validators(pubkeys_slice, epochs_slice)
                             .await
                             .map_err(|e| {
                                 format!("Failed query for seen validators: {:?}", e)
                             })
                             .map(|result| result.data)
                     })
                     .await
                     .map_err(|e| format!("Failed query for seen validators: {}", e));

                 // Send shutdown signal if necessary
                 match doppelganger_detected {
                     Ok(true) => {
                         crit!(
                                     log,
                                     "Doppelganger detected! Shutting down. Ensure you aren't already \
                                     running a validator client with the same keys."
                                 );

                         let _ = self
                             .context
                             .executor
                             .shutdown_sender()
                             .try_send("Doppelganger detected.");
                         break;
                     }
                     Ok(false) => continue,
                     Err(e) => {
                         crit!(log, "Failed complete query for doppelganger detection... Exiting."; "error" => format!("{:?}", e));
                         let _ = self
                             .context
                             .executor
                             .shutdown_sender()
                             .try_send("Doppelganger detected.");
                         break;
                     }
                 }
             }
         } else {
             error!(log, "Unable to read slot clock");
         }
    }

}