//! The "Doppelganger" service is an **imperfect** mechanism to try and prevent the validator client
//! from starting whilst any of its validators are actively producing messages on the network.
//!
//! The mechanism works roughly like so: when the validator client starts or a new validator is
//! added, that validator is assigned a number of "remaining epochs". The doppelganger service
//! periodically poll the beacon node to if that validator has been observed to produce
//! blocks/attestations in each epoch. After the doppelganger service is confident that an epoch has
//! passed without observing that validator, it will decrease the remaining epochs by one. Once the
//! remaining epochs is zero, the doppelganger will consider that validator to be safe-enough to
//! start.
//!
//! If a doppelganger is detected, the entire validator client will exit.
//!
//! For validators started during the genesis epoch, there is **no doppelganger protection!**. This
//! prevents a stale-mate where all validators will cease to function for a few epochs and then all
//! start at the same time.
//!
//! ## Warning
//!
//! The Doppelganger service is not perfect. It makes assumptions that any existing validator is
//! performing their duties as required and that the network is able to relay those messages to the
//! beacon node. Among other loop-holes, two validator clients started at the same time will not
//! detect each other.
//!
//! Doppelganger protection is a best-effort, last-line-of-defence mitigation. Do not rely upon it.

use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use parking_lot::RwLock;
use slog::{crit, error, info};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use task_executor::ShutdownReason;
use tokio::time::sleep;
use types::{Epoch, EthSpec, PublicKeyBytes, Slot};

/// A wrapper around `PublicKeyBytes` which encodes information about the status of a validator
/// pubkey with regards to doppelganger protection.
pub enum DoppelgangerStatus {
    /// Doppelganger protection has approved this for signing.
    ///
    /// This is because the service is disabled, or the service has waited some period of time to
    /// detect other instances of this key on the network.
    SigningEnabled(PublicKeyBytes),
    /// Doppelganger protection is still waiting to detect other instances.
    ///
    /// Do not use this pubkey for signing slashable messages!!
    ///
    /// However, it can safely be used for other non-slashable operations (e.g., collecting duties
    /// or subscribing to subnets).
    SigningDisabled(PublicKeyBytes),
    /// This pubkey is unknown to the doppelganger service.
    ///
    /// This represents a serious internal error in the program. This validator will be permanently
    /// disabled!
    UnknownToDoppelganger(PublicKeyBytes),
}

impl DoppelgangerStatus {
    /// Only return a pubkey if it is explicitly safe for doppelganger protection.
    ///
    /// If `Some(pubkey)` is returned, doppelganger has declared it safe for signing.
    ///
    /// ## Note
    ///
    /// "Safe" is only best-effort by doppelganger. There is no guarantee that a doppelganger
    /// doesn't exist.
    pub fn only_safe(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::SigningDisabled(_) => None,
            DoppelgangerStatus::UnknownToDoppelganger(_) => None,
        }
    }

    /// Returns a key regardless of whether or not doppelganger has approved it. Such a key might be
    /// used for signing, duties collection or other activities.
    ///
    /// If the validator is unknown to doppelganger then `None` will be returned.
    pub fn ignored(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::SigningDisabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::UnknownToDoppelganger(_) => None,
        }
    }
}

/// The number of epochs that must be checked before we assume that there are no other duplicate
/// validators on the network.
pub const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 2;

/// Store the per-validator status of doppelganger checking.
pub struct DopplegangerState {
    /// The next epoch for which the validator should be checked for liveness.
    ///
    /// Whilst `self.remaining_epochs > 0`, if a validator is found to be live in this epoch or any
    /// following then we consider them to have an active doppelganger.
    ///
    /// Regardless of `self.remaining_epochs`, never indicate for a doppelganger for epochs that are
    /// below `next_check_epoch`. This is to avoid the scenario where a user reboots their VC inside
    /// a single epoch and we detect the activity of that previous process as doppelganger activity,
    /// even when it's not running anymore.
    next_check_epoch: Epoch,
    /// The number of epochs that must be checked before this validator is considered
    /// doppelganger-free.
    remaining_epochs: u64,
}

impl DopplegangerState {
    /// Returns `true` if the validator is *not* safe to sign.
    fn requires_further_checks(&self) -> bool {
        self.remaining_epochs > 0
    }
}

#[derive(Clone)]
pub struct DoppelgangerService<T, E: EthSpec> {
    pub slot_clock: T,
    // The `Box` avoids an infinite-sized struct due to the circular dependency of the validator
    // store and the doppleganger service.
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
                    let slot_duration = doppelganger_service.slot_clock.slot_duration();

                    if let Some(duration_to_next_slot) =
                        doppelganger_service.slot_clock.duration_to_next_slot()
                    {
                        // Run the doppelganger protection check 75% through each epoch. This
                        // *should* mean that the BN has seen the blocks and attestations for this
                        // slot.
                        sleep(duration_to_next_slot + (slot_duration / 4) * 3).await;
                    } else {
                        // Just sleep for one slot if we are unable to read the system clock, this gives
                        // us an opportunity for the clock to eventually come good.
                        sleep(slot_duration).await;
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

    /// Returns the current status of the `validator` in the doppelganger protection process.
    pub fn validator_status(&self, validator: PublicKeyBytes) -> DoppelgangerStatus {
        self.doppelganger_states
            .read()
            .get(&validator)
            .map(|v| {
                if v.requires_further_checks() {
                    DoppelgangerStatus::SigningDisabled(validator)
                } else {
                    DoppelgangerStatus::SigningEnabled(validator)
                }
            })
            .unwrap_or_else(|| {
                crit!(
                    self.context.log(),
                    "Validator unknown to doppelganger service";
                    "msg" => "preventing validator from performing duties",
                    "pubkey" => ?validator
                );
                DoppelgangerStatus::UnknownToDoppelganger(validator)
            })
    }

    /// Register a new validator with the doppelganger service.
    ///
    /// Validators added during the genesis epoch will not have doppelganger protection applied to
    /// them.
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
            // would be pointless.
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

    /// Contact the beacon node and try to detect if there are any doppelgangers, updating the state
    /// of `self`.
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
        // Any pubkeys which do not have a known validator index will be ignored, preventing them
        // from progressing through doppelganger protection until their indices are resolved.
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

        // Request the current epoch liveness state from the beacon node.
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

        // Perform a loop through the current and previous epoch responses and detect any violators.
        //
        // A following loop will update the states of each validator, depending on whether or not
        // any violators were detected here.
        let mut violators = vec![];
        for response in previous_epoch_responses
            .iter()
            .chain(current_epoch_responses.iter())
        {
            if !response.is_live {
                continue;
            }

            // Resolve the index from the server response back to a public key.
            let pubkey = indices_map
                .get(&response.index)
                // Abort the routine if inconsistency is detected.
                .ok_or_else(|| {
                    format!(
                        "inconsistent indices map for validator index {}",
                        response.index
                    )
                })?;

            let next_check_epoch = self
                .doppelganger_states
                .read()
                .get(&pubkey)
                // Abort the routine if inconsistency is detected.
                .ok_or_else(|| format!("inconsistent states for validator pubkey {}", pubkey))?
                .next_check_epoch;

            if response.is_live && next_check_epoch >= response.epoch {
                violators.push(response.index);
            }
        }

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

        // The concept of "epoch satisfaction" is that for some epoch `e` we are *satisified* that
        // we've waited long enough such that we don't expect to see any more consensus messages
        // for that epoch.
        //
        // As it stands now, we consider epoch `e` to be satisfied once we're in the last slot of
        // epoch `e + 1`.
        //
        // The reasoning for this choice of satisfaction slot is that by this point we've
        // *probably* seen all the blocks that are permitted to contain attestations from epoch `e`.
        let previous_epoch_satisfaction_slot = previous_epoch
            .saturating_add(1_u64)
            .end_slot(E::slots_per_epoch());
        let previous_epoch_is_satisfied = request_slot >= previous_epoch_satisfaction_slot;

        // Iterate through all the previous epoch responses, updating `self.doppelganger_states`.
        //
        // Do not bother iterating through the current epoch responses since they've already been
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

            // Resolve the index from the server response back to a public key.
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
                // This has the effect of stopping validator activity even if the validator client
                // fails to shut down.
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

        // Attempt to shutdown the validator client if there are any detected duplicate validators.
        if violators_exist {
            let _ = self
                .context
                .executor
                .shutdown_sender()
                .try_send(ShutdownReason::Failure("Doppelganger detected."))
                .map_err(|e| format!("Could not send shutdown signal: {}", e))?;
        }

        Ok(())
    }
}
