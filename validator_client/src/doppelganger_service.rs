use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use parking_lot::RwLock;
use slog::{crit, error, info};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::sleep;
use types::{Epoch, EthSpec, PublicKeyBytes, Slot};

pub const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 2;

// TODO: add reasoning for this.
pub const EPOCH_SATISFACTION_DEPTH: u64 = 2;

pub struct DopplegangerState {
    next_check_epoch: Epoch,
    remaining_epochs: u64,
}

impl DopplegangerState {
    fn requires_further_checks(&self) -> bool {
        self.remaining_epochs > 0
    }
}

#[derive(Clone)]
pub struct DoppelgangerService<T, E: EthSpec> {
    pub slot_clock: T,
    // The `Box` is used to avoid an infinite-sized struct due to the circular dependency of the
    // validator store and the doppleganger service.
    pub validator_store: Box<ValidatorStore<T, E>>,
    pub beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    pub context: RuntimeContext<E>,
    pub doppelganger_states: Arc<RwLock<HashMap<PublicKeyBytes, DopplegangerState>>>,
}

impl<T: 'static + SlotClock, E: EthSpec> DoppelgangerService<T, E> {
    pub fn start_update_service(self) -> Result<(), String> {
        let log = self.context.log().clone();

        info!(
            log,
            "Doppelganger detection service started";
        );

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

                    if let Some(slot) = doppelganger_service.slot_clock.now() {
                        if let Err(e) = doppelganger_service.detect_doppelgangers(slot).await {
                            error!(
                                log,
                                "Error during doppelganger detection";
                                "error" => ?e
                            );
                        }
                    }
                }
            },
            "doppelganger_service",
        );
        Ok(())
    }

    pub fn validator_should_sign(&self, validator: &PublicKeyBytes) -> Option<bool> {
        self.doppelganger_states
            .read()
            .get(validator)
            .map(|v| !v.requires_further_checks())
    }

    pub fn register_new_validator(&self, validator: PublicKeyBytes) -> Result<(), String> {
        let current_epoch = self
            .slot_clock
            .now()
            .ok_or_else(|| "Unable to read slot clock when registering validator".to_string())?
            .epoch(E::slots_per_epoch());
        let genesis_epoch = self.slot_clock.genesis_slot().epoch(E::slots_per_epoch());

        let remaining_epochs = if current_epoch <= genesis_epoch {
            // Disable doppelganger protection when the validator was initialized before genesis.
            //
            // Without this, all validators would simply miss the first
            // `DEFAULT_REMAINING_DETECTION_EPOCHS` epochs and then all start at the same time. This
            // would be pointless and damaging.
            //
            // The downside of this is that no validators have doppelganger protection at genesis.
            // It's an unfortunate trade-off.
            0
        } else {
            DEFAULT_REMAINING_DETECTION_EPOCHS
        };

        let state = DopplegangerState {
            next_check_epoch: current_epoch.saturating_add(1_u64),
            remaining_epochs,
        };

        self.doppelganger_states.write().insert(validator, state);

        Ok(())
    }

    async fn detect_doppelgangers(&self, request_slot: Slot) -> Result<(), String> {
        let log = self.context.log().clone();

        let request_epoch = request_slot.epoch(E::slots_per_epoch());

        // Get the list of all registered public keys which still require additional doppelganger
        // checks.
        //
        // It is important to ensure that the `self.doppelganger_states` lock is not interleaved with
        // any other locks. This is why `detection_indices` are determined in a separate routine.
        let detection_pubkeys = self
            .doppelganger_states
            .read()
            .iter()
            .filter_map(|(pubkey, state)| {
                if state.requires_further_checks() {
                    Some(*pubkey)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Maps validator indices to pubkeys.
        let mut indices_map = HashMap::with_capacity(detection_pubkeys.len());

        // Resolve the list of pubkeys to indices.
        //
        // Any pubkeys which do not have a known validator index will be ignored.
        let detection_indices = detection_pubkeys
            .iter()
            // Note: mutation of external state inside this `filter_map`.
            .filter_map(|pubkey| {
                let index = self.validator_store.validator_index(pubkey)?;
                indices_map.insert(index, pubkey);
                Some(index)
            })
            .collect::<Vec<_>>();

        if detection_indices.is_empty() {
            // Nothing to do.
            return Ok(());
        }

        let previous_epoch = request_epoch.saturating_sub(1_u64);

        // Explicit slice to satisfy borrow checker.
        let detection_indices_slice = detection_indices.as_slice();

        // Request the previous epoch liveness state from the beacon node.
        let previous_epoch_responses = self
            .beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .post_lighthouse_liveness(detection_indices_slice, request_epoch)
                    .await
                    .map_err(|e| format!("Failed query for validator liveness: {:?}", e))
                    .map(|result| result.data)
            })
            .await
            .map_err(|e| format!("Failed query for validator liveness: {}", e))?;

        // Request the previous epoch liveness state from the beacon node.
        let current_epoch_responses = self
            .beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .post_lighthouse_liveness(detection_indices_slice, request_epoch)
                    .await
                    .map_err(|e| format!("Failed query for validator liveness: {:?}", e))
                    .map(|result| result.data)
            })
            .await
            .map_err(|e| format!("Failed query for validator liveness: {}", e))?;

        // Collect any duplicate validators across the previous and current epochs.
        let violators = previous_epoch_responses
            .iter()
            .chain(current_epoch_responses.iter())
            .filter(|response| response.is_live)
            .map(|response| response.index)
            .collect::<Vec<_>>();
        let violators_exist = !violators.is_empty();

        if violators_exist {
            crit!(
                log,
                "Doppleganger(s) detected";
                "msg" => "A doppelganger occurs when two different validator clients run the \
                    same public key. This validator client detected another instance of a local \
                    validator on the network and is shutting down to prevent potential slashable \
                    offences. Ensure that you are not running a duplicate or overlapping \
                    validator client",
                "doppelganger_indices" => ?violators
            )
        }

        // The slot at which we become confident that we have seen enough of the previous epoch to
        // detect any duplicate validators.
        let previous_epoch_satisfaction_slot = previous_epoch
            .start_slot(E::slots_per_epoch())
            .saturating_add(EPOCH_SATISFACTION_DEPTH);
        let previous_epoch_is_satisfied = request_slot >= previous_epoch_satisfaction_slot;

        // Iterate through all the previous epoch responses, updating `self.doppelganger_states`.
        //
        // Do not bother iterating through the current epoch response since they've already been
        // checked for violators and they don't result in updating the state.
        for response in &previous_epoch_responses {
            // Sanity check response from the server.
            //
            // Abort the entire routine if the server starts returning junk.
            if response.epoch != request_epoch {
                return Err(format!(
                    "beacon node returned epoch {}, expecting {}",
                    response.epoch, request_epoch
                ));
            }

            let pubkey = indices_map
                .get(&response.index)
                // Abort the routine if inconsistency is detected.
                .ok_or_else(|| {
                    format!(
                        "inconsistent indices map for validator index {}",
                        response.index
                    )
                })?;

            // Hold the lock on `self` for the rest of this function.
            //
            // !! IMPORTANT !!
            //
            // There is a write-lock being held, avoid interacting with locks until it is dropped.
            let mut doppelganger_states = self.doppelganger_states.write();
            let doppelganger_state = doppelganger_states
                .get_mut(&pubkey)
                // Abort the routine if inconsistency is detected.
                .ok_or_else(|| format!("inconsistent states for validator pubkey {}", pubkey))?;

            let is_newly_satisfied_epoch = previous_epoch_is_satisfied
                && previous_epoch >= doppelganger_state.next_check_epoch;

            if violators_exist {
                // If a single doppelganger is detected, enable doppelganger checks on all
                // validators forever (technically only 2**64 epochs).
                //
                // This has the effect of stopping all validator activity, even if the validator
                // client fails to shut down.
                doppelganger_state.remaining_epochs = u64::max_value();
            } else if !response.is_live && is_newly_satisfied_epoch {
                // The validator has successfully completed doppelganger checks for a new epoch.
                doppelganger_state.remaining_epochs =
                    doppelganger_state.remaining_epochs.saturating_sub(1);

                info!(
                    log,
                    "Found no doppelganger";
                    "further_checks_remaining" => doppelganger_state.remaining_epochs,
                    "epoch" => response.index,
                    "validator_index" => response.index
                );

                if doppelganger_state.remaining_epochs == 0 {
                    info!(
                        log,
                        "Doppleganger detection complete";
                        "msg" => "starting validator",
                        "validator_index" => response.index
                    );
                }
            }
        }

        if violators_exist {
            // Attempt to shutdown the validator client.
            let _ = self
                .context
                .executor
                .shutdown_sender()
                .try_send("Doppelganger detected.")
                .map_err(|e| format!("Could not send shutdown signal: {}", e))?;
        }

        Ok(())
    }
}
