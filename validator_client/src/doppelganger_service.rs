//! The "Doppelganger" service is an **imperfect** mechanism to try and prevent the validator client
//! from starting whilst any of its validators are actively producing messages on the network.
//!
//! The mechanism works roughly like so: when the validator client starts or a new validator is
//! added, that validator is assigned a number of "remaining epochs". The doppelganger service
//! periodically polls the beacon node to see if that validator has been observed to produce
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
//! ## Caveat
//!
//! Presently doppelganger protection will never advance if the call at the last slot of each epoch
//! fails. This call is critical to ensuring that validators are able to start performing.
//!
//! ## Disclaimer
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
use eth2::types::LivenessResponseData;
use parking_lot::RwLock;
use slog::{crit, error, info, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use task_executor::ShutdownReason;
use tokio::time::sleep;
use types::{Epoch, EthSpec, PublicKeyBytes, Slot};

/// A wrapper around `PublicKeyBytes` which encodes information about the status of a validator
/// pubkey with regards to doppelganger protection.
#[derive(Debug, PartialEq)]
pub enum DoppelgangerStatus {
    /// Doppelganger protection has approved this for signing.
    ///
    /// This is because the service has waited some period of time to
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
    /// used for signing non-slashable messages, duties collection or other activities.
    ///
    /// If the validator is unknown to doppelganger then `None` will be returned.
    pub fn ignored(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::SigningDisabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::UnknownToDoppelganger(_) => None,
        }
    }

    /// Only return a pubkey if it will not be used for signing due to doppelganger detection.
    pub fn only_unsafe(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(_) => None,
            DoppelgangerStatus::SigningDisabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::UnknownToDoppelganger(pubkey) => Some(pubkey),
        }
    }
}

struct LivenessResponses {
    current_epoch_responses: Vec<LivenessResponseData>,
    previous_epoch_responses: Vec<LivenessResponseData>,
}

/// The number of epochs that must be checked before we assume that there are no other duplicate
/// validators on the network.
pub const DEFAULT_REMAINING_DETECTION_EPOCHS: u64 = 1;

/// Store the per-validator status of doppelganger checking.
#[derive(Debug, PartialEq)]
pub struct DoppelgangerState {
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

impl DoppelgangerState {
    /// Returns `true` if the validator is *not* safe to sign.
    fn requires_further_checks(&self) -> bool {
        self.remaining_epochs > 0
    }

    /// Updates the `DoppelgangerState` to consider the given `Epoch`'s doppelganger checks
    /// completed.
    fn complete_detection_in_epoch(&mut self, epoch: Epoch) {
        // The validator has successfully completed doppelganger checks for a new epoch.
        self.remaining_epochs = self.remaining_epochs.saturating_sub(1);

        // Since we just satisfied the `previous_epoch`, the next epoch to satisfy should be
        // the one following that.
        self.next_check_epoch = epoch.saturating_add(1_u64);
    }
}

/// Perform two requests to the BN to obtain the liveness data for `validator_indices`. One
/// request will pertain to the `current_epoch`, the other to the `previous_epoch`.
///
/// If the BN fails to respond to either of these requests, simply return an empty response.
/// This behaviour is to help prevent spurious failures on the BN from needlessly preventing
/// doppelganger progression.
async fn beacon_node_liveness<'a, T: 'static + SlotClock, E: EthSpec>(
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    log: Logger,
    current_epoch: Epoch,
    validator_indices: Vec<u64>,
) -> LivenessResponses {
    let validator_indices = validator_indices.as_slice();

    let previous_epoch = current_epoch.saturating_sub(1_u64);

    let previous_epoch_responses = if previous_epoch == current_epoch {
        // If the previous epoch and the current epoch are the same, don't bother requesting the
        // previous epoch indices.
        //
        // In such a scenario it will be possible to detect validators but we will never update
        // any of the doppelganger states.
        vec![]
    } else {
        // Request the previous epoch liveness state from the beacon node.
        beacon_nodes
            .first_success(RequireSynced::Yes, |beacon_node| async move {
                beacon_node
                    .post_lighthouse_liveness(validator_indices, previous_epoch)
                    .await
                    .map_err(|e| format!("Failed query for validator liveness: {:?}", e))
                    .map(|result| result.data)
            })
            .await
            .unwrap_or_else(|e| {
                crit!(
                    log,
                    "Failed previous epoch liveness query";
                    "error" => %e,
                    "previous_epoch" => %previous_epoch,
                );
                // Return an empty vec. In effect, this means to keep trying to make doppelganger
                // progress even if some of the calls are failing.
                vec![]
            })
    };

    // Request the current epoch liveness state from the beacon node.
    let current_epoch_responses = beacon_nodes
        .first_success(RequireSynced::Yes, |beacon_node| async move {
            beacon_node
                .post_lighthouse_liveness(validator_indices, current_epoch)
                .await
                .map_err(|e| format!("Failed query for validator liveness: {:?}", e))
                .map(|result| result.data)
        })
        .await
        .unwrap_or_else(|e| {
            crit!(
                log,
                "Failed current epoch liveness query";
                "error" => %e,
                "current_epoch" => %current_epoch,
            );
            // Return an empty vec. In effect, this means to keep trying to make doppelganger
            // progress even if some of the calls are failing.
            vec![]
        });

    // Alert the user if the beacon node is omitting validators from the response.
    //
    // This is not perfect since the validator might return duplicate entries, but it's a quick
    // and easy way to detect issues.
    if validator_indices.len() != current_epoch_responses.len()
        || current_epoch_responses.len() != previous_epoch_responses.len()
    {
        error!(
            log,
            "Liveness query omitted validators";
            "previous_epoch_response" => previous_epoch_responses.len(),
            "current_epoch_response" => current_epoch_responses.len(),
            "requested" => validator_indices.len(),
        )
    }

    LivenessResponses {
        current_epoch_responses,
        previous_epoch_responses,
    }
}

pub struct DoppelgangerService {
    doppelganger_states: RwLock<HashMap<PublicKeyBytes, DoppelgangerState>>,
    log: Logger,
}

impl DoppelgangerService {
    pub fn new(log: Logger) -> Self {
        Self {
            doppelganger_states: <_>::default(),
            log,
        }
    }

    /// Starts a reoccurring future which will try to keep the doppelganger service updated each
    /// slot.
    pub fn start_update_service<E: EthSpec, T: 'static + SlotClock>(
        service: Arc<Self>,
        context: RuntimeContext<E>,
        validator_store: Arc<ValidatorStore<T, E>>,
        beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
        slot_clock: T,
    ) -> Result<(), String> {
        // Define the `get_index` function as one that uses the validator store.
        let get_index = move |pubkey| validator_store.validator_index(&pubkey);

        // Define the `get_liveness` function as one that queries the beacon node API.
        let log = service.log.clone();
        let get_liveness = move |current_epoch, validator_indices| {
            beacon_node_liveness(
                beacon_nodes.clone(),
                log.clone(),
                current_epoch,
                validator_indices,
            )
        };

        let mut shutdown_sender = context.executor.shutdown_sender();
        let log = service.log.clone();
        let mut shutdown_func = move || {
            if let Err(e) =
                shutdown_sender.try_send(ShutdownReason::Failure("Doppelganger detected."))
            {
                crit!(
                    log,
                    "Failed to send shutdown signal";
                    "msg" => "terminate this process immediately",
                    "error" => ?e
                );
            }
        };

        info!(
            service.log,
            "Doppelganger detection service started";
        );

        context.executor.spawn(
            async move {
                loop {
                    let slot_duration = slot_clock.slot_duration();

                    if let Some(duration_to_next_slot) = slot_clock.duration_to_next_slot() {
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

                    if let Some(slot) = slot_clock.now() {
                        if let Err(e) = service
                            .detect_doppelgangers::<E, _, _, _, _>(
                                slot,
                                &get_index,
                                &get_liveness,
                                &mut shutdown_func,
                            )
                            .await
                        {
                            error!(
                                service.log,
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
                    self.log,
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
    pub fn register_new_validator<E: EthSpec, T: SlotClock>(
        &self,
        validator: PublicKeyBytes,
        slot_clock: &T,
    ) -> Result<(), String> {
        let current_epoch = slot_clock
            // If registering before genesis, use the genesis slot.
            .now_or_genesis()
            .ok_or_else(|| "Unable to read slot clock when registering validator".to_string())?
            .epoch(E::slots_per_epoch());
        let genesis_epoch = slot_clock.genesis_slot().epoch(E::slots_per_epoch());

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

        let state = DoppelgangerState {
            next_check_epoch: current_epoch.saturating_add(1_u64),
            remaining_epochs,
        };

        self.doppelganger_states.write().insert(validator, state);

        Ok(())
    }

    /// Contact the beacon node and try to detect if there are any doppelgangers, updating the state
    /// of `self`.
    ///
    /// ## Notes
    ///
    /// This function is relatively complex when it comes to generic parameters. This is to allow
    /// for simple unit testing. Using these generics, we can test the `DoppelgangerService` without
    /// needing a BN API or a `ValidatorStore`.
    async fn detect_doppelgangers<E, I, L, F, S>(
        &self,
        request_slot: Slot,
        get_index: &I,
        get_liveness: &L,
        shutdown_func: &mut S,
    ) -> Result<(), String>
    where
        E: EthSpec,
        I: Fn(PublicKeyBytes) -> Option<u64>,
        L: Fn(Epoch, Vec<u64>) -> F,
        F: Future<Output = LivenessResponses>,
        S: FnMut(),
    {
        // Get all validators with active doppelganger protection.
        let indices_map = self.compute_detection_indices_map(get_index);

        if indices_map.is_empty() {
            // Nothing to do.
            return Ok(());
        }

        // Get a list of indices to provide to the BN API.
        let indices_only = indices_map.iter().map(|(index, _)| *index).collect();

        // Pull the liveness responses from the BN.
        let request_epoch = request_slot.epoch(E::slots_per_epoch());
        let liveness_responses = get_liveness(request_epoch, indices_only).await;

        // Process the responses, attempting to detect doppelgangers.
        self.process_liveness_responses::<E, _>(
            request_slot,
            liveness_responses,
            &indices_map,
            shutdown_func,
        )
    }

    /// Get a map of `validator_index` -> `validator_pubkey` for all validators still requiring
    /// further doppelganger checks.
    ///
    /// Any validator with an unknown index will be omitted from these results.
    fn compute_detection_indices_map<F>(&self, get_index: &F) -> HashMap<u64, PublicKeyBytes>
    where
        F: Fn(PublicKeyBytes) -> Option<u64>,
    {
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

        // It is important to ensure that the `self.doppelganger_states` lock is not interleaved with
        // any other locks. That is why this is a separate loop to the one that generates
        // `detection_pubkeys`.
        for pubkey in detection_pubkeys {
            if let Some(index) = get_index(pubkey) {
                indices_map.insert(index, pubkey);
            }
        }

        indices_map
    }

    /// Process the liveness responses from the BN, potentially updating doppelganger states or
    /// shutting down the VC.
    fn process_liveness_responses<E: EthSpec, S>(
        &self,
        request_slot: Slot,
        liveness_responses: LivenessResponses,
        indices_map: &HashMap<u64, PublicKeyBytes>,
        shutdown_func: &mut S,
    ) -> Result<(), String>
    where
        S: FnMut(),
    {
        let request_epoch = request_slot.epoch(E::slots_per_epoch());
        let previous_epoch = request_epoch.saturating_sub(1_u64);
        let LivenessResponses {
            previous_epoch_responses,
            current_epoch_responses,
        } = liveness_responses;

        // Perform a loop through the current and previous epoch responses and detect any violators.
        //
        // A following loop will update the states of each validator, depending on whether or not
        // any violators were detected here.
        let mut violators = HashSet::new();
        for response in previous_epoch_responses
            .iter()
            .chain(current_epoch_responses.iter())
        {
            if !response.is_live {
                continue;
            }

            // Resolve the index from the server response back to a public key.
            let pubkey = if let Some(pubkey) = indices_map.get(&response.index) {
                pubkey
            } else {
                crit!(
                    self.log,
                    "Inconsistent indices map";
                    "validator_index" => response.index,
                );
                // Skip this result if an inconsistency is detected.
                continue;
            };

            let next_check_epoch = if let Some(state) = self.doppelganger_states.read().get(pubkey)
            {
                state.next_check_epoch
            } else {
                crit!(
                    self.log,
                    "Inconsistent doppelganger state";
                    "validator_pubkey" => ?pubkey,
                );
                // Skip this result if an inconsistency is detected.
                continue;
            };

            if response.is_live && next_check_epoch <= response.epoch {
                violators.insert(response.index);
            }
        }

        let violators_exist = !violators.is_empty();
        if violators_exist {
            crit!(
                self.log,
                "Doppelganger(s) detected";
                "msg" => "A doppelganger occurs when two different validator clients run the \
                    same public key. This validator client detected another instance of a local \
                    validator on the network and is shutting down to prevent potential slashable \
                    offences. Ensure that you are not running a duplicate or overlapping \
                    validator client",
                "doppelganger_indices" => ?violators
            )
        }

        // The concept of "epoch satisfaction" is that for some epoch `e` we are *satisfied* that
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
            if response.epoch != previous_epoch {
                return Err(format!(
                    "beacon node returned epoch {}, expecting {}",
                    response.epoch, previous_epoch
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
                .get_mut(pubkey)
                // Abort the routine if inconsistency is detected.
                .ok_or_else(|| format!("inconsistent states for validator pubkey {}", pubkey))?;

            // If a single doppelganger is detected, enable doppelganger checks on all
            // validators forever (technically only 2**64 epochs).
            //
            // This has the effect of stopping validator activity even if the validator client
            // fails to shut down.
            //
            // A weird side-effect is that the BN will keep getting liveness queries that will be
            // ignored by the VC. Since the VC *should* shutdown anyway, this seems fine.
            if violators_exist {
                doppelganger_state.remaining_epochs = u64::MAX;
                continue;
            }

            let is_newly_satisfied_epoch = previous_epoch_is_satisfied
                && previous_epoch >= doppelganger_state.next_check_epoch;

            if !response.is_live && is_newly_satisfied_epoch {
                // Update the `doppelganger_state` to consider the previous epoch's checks complete.
                doppelganger_state.complete_detection_in_epoch(previous_epoch);

                info!(
                    self.log,
                    "Found no doppelganger";
                    "further_checks_remaining" => doppelganger_state.remaining_epochs,
                    "epoch" => response.epoch,
                    "validator_index" => response.index
                );

                if doppelganger_state.remaining_epochs == 0 {
                    info!(
                        self.log,
                        "Doppelganger detection complete";
                        "msg" => "starting validator",
                        "validator_index" => response.index
                    );
                }
            }
        }

        // Attempt to shutdown the validator client if there are any detected duplicate validators.
        if violators_exist {
            shutdown_func();
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use environment::null_logger;
    use futures::executor::block_on;
    use slot_clock::TestingSlotClock;
    use std::collections::HashSet;
    use std::future;
    use std::time::Duration;
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        MainnetEthSpec,
    };

    const DEFAULT_VALIDATORS: usize = 8;

    const GENESIS_TIME: Duration = Duration::from_secs(42);
    const SLOT_DURATION: Duration = Duration::from_secs(1);

    type E = MainnetEthSpec;

    fn genesis_epoch() -> Epoch {
        E::default_spec().genesis_slot.epoch(E::slots_per_epoch())
    }

    fn check_detection_indices(detection_indices: &[u64]) {
        assert_eq!(
            detection_indices.iter().copied().collect::<HashSet<_>>(),
            (0..DEFAULT_VALIDATORS as u64).collect::<HashSet<_>>(),
            "all validators should be included in detection indices"
        );
    }

    struct TestBuilder {
        validator_count: usize,
    }

    impl Default for TestBuilder {
        fn default() -> Self {
            Self {
                validator_count: DEFAULT_VALIDATORS,
            }
        }
    }

    impl TestBuilder {
        fn build(self) -> TestScenario {
            let mut rng = XorShiftRng::from_seed([42; 16]);
            let slot_clock = TestingSlotClock::new(Slot::new(0), GENESIS_TIME, SLOT_DURATION);
            let log = null_logger().unwrap();

            TestScenario {
                validators: (0..self.validator_count)
                    .map(|_| PublicKeyBytes::random_for_test(&mut rng))
                    .collect(),
                doppelganger: DoppelgangerService::new(log),
                slot_clock,
            }
        }
    }

    struct TestScenario {
        validators: Vec<PublicKeyBytes>,
        doppelganger: DoppelgangerService,
        slot_clock: TestingSlotClock,
    }

    impl TestScenario {
        pub fn pubkey_to_index_map(&self) -> HashMap<PublicKeyBytes, u64> {
            self.validators
                .iter()
                .enumerate()
                .map(|(index, pubkey)| (*pubkey, index as u64))
                .collect()
        }

        pub fn set_slot(self, slot: Slot) -> Self {
            self.slot_clock.set_slot(slot.into());
            self
        }

        pub fn set_current_time(self, time: Duration) -> Self {
            self.slot_clock.set_current_time(time);
            self
        }

        pub fn assert_prior_to_genesis(self) -> Self {
            assert!(self.slot_clock.is_prior_to_genesis().unwrap());
            self
        }

        pub fn register_all_in_doppelganger_protection_if_enabled(self) -> Self {
            let mut this = self;
            for i in 0..this.validators.len() {
                this = this.register_validator(i as u64);
            }
            this
        }

        pub fn register_validators(self, validators: &[u64]) -> Self {
            let mut this = self;
            for i in validators {
                this = this.register_validator(*i);
            }
            this
        }

        pub fn register_validator(self, index: u64) -> Self {
            let pubkey = *self
                .validators
                .get(index as usize)
                .expect("index should exist");

            self.doppelganger
                .register_new_validator::<E, _>(pubkey, &self.slot_clock)
                .unwrap();
            self.doppelganger
                .doppelganger_states
                .read()
                .get(&pubkey)
                .expect("validator should be registered");

            self
        }

        pub fn assert_all_enabled(self) -> Self {
            /*
             * 1. Ensure all validators have the correct status.
             */
            for validator in &self.validators {
                assert_eq!(
                    self.doppelganger.validator_status(*validator),
                    DoppelgangerStatus::SigningEnabled(*validator),
                    "all validators should be enabled"
                );
            }

            /*
             * 2. Ensure a correct detection indices map is generated.
             */
            let pubkey_to_index = self.pubkey_to_index_map();
            let generated_map = self
                .doppelganger
                .compute_detection_indices_map(&|pubkey| pubkey_to_index.get(&pubkey).copied());
            assert!(
                generated_map.is_empty(),
                "there should be no indices for detection if all validators are enabled"
            );

            self
        }

        pub fn assert_all_disabled(self) -> Self {
            /*
             * 1. Ensure all validators have the correct status.
             */
            for validator in &self.validators {
                assert_eq!(
                    self.doppelganger.validator_status(*validator),
                    DoppelgangerStatus::SigningDisabled(*validator),
                    "all validators should be disabled"
                );
            }

            /*
             * 2. Ensure a correct detection indices map is generated.
             */
            let pubkey_to_index = self.pubkey_to_index_map();
            let generated_map = self
                .doppelganger
                .compute_detection_indices_map(&|pubkey| pubkey_to_index.get(&pubkey).copied());

            assert_eq!(
                pubkey_to_index.len(),
                generated_map.len(),
                "should declare all indices for detection"
            );
            for (pubkey, index) in pubkey_to_index {
                assert_eq!(
                    generated_map.get(&index),
                    Some(&pubkey),
                    "map should be consistent"
                );
            }

            self
        }

        pub fn assert_all_states(self, state: &DoppelgangerState) -> Self {
            let mut this = self;
            for i in 0..this.validators.len() {
                this = this.assert_state(i as u64, state);
            }
            this
        }

        pub fn assert_state(self, index: u64, state: &DoppelgangerState) -> Self {
            let pubkey = *self
                .validators
                .get(index as usize)
                .expect("index should exist");

            assert_eq!(
                self.doppelganger
                    .doppelganger_states
                    .read()
                    .get(&pubkey)
                    .expect("validator should be present"),
                state,
                "validator should match provided state"
            );

            self
        }

        pub fn assert_unregistered(self, index: u64) -> Self {
            let pubkey = *self
                .validators
                .get(index as usize)
                .expect("index should exist in test scenario");

            assert!(
                self.doppelganger
                    .doppelganger_states
                    .read()
                    .get(&pubkey)
                    .is_none(),
                "validator should not be present in states"
            );

            assert_eq!(
                self.doppelganger.validator_status(pubkey),
                DoppelgangerStatus::UnknownToDoppelganger(pubkey),
                "validator status should be unknown"
            );

            self
        }
    }

    #[test]
    fn enabled_in_genesis_epoch() {
        for slot in genesis_epoch().slot_iter(E::slots_per_epoch()) {
            TestBuilder::default()
                .build()
                .set_slot(slot)
                .register_all_in_doppelganger_protection_if_enabled()
                .assert_all_enabled()
                .assert_all_states(&DoppelgangerState {
                    next_check_epoch: genesis_epoch() + 1,
                    remaining_epochs: 0,
                });
        }
    }

    #[test]
    fn disabled_after_genesis_epoch() {
        let epoch = genesis_epoch() + 1;

        for slot in epoch.slot_iter(E::slots_per_epoch()) {
            TestBuilder::default()
                .build()
                .set_slot(slot)
                .register_all_in_doppelganger_protection_if_enabled()
                .assert_all_disabled()
                .assert_all_states(&DoppelgangerState {
                    next_check_epoch: epoch + 1,
                    remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
                });
        }
    }

    #[test]
    fn unregistered_validator() {
        // Non-genesis epoch
        let epoch = genesis_epoch() + 2;

        TestBuilder::default()
            .build()
            .set_slot(epoch.start_slot(E::slots_per_epoch()))
            // Register only validator 1.
            .register_validator(1)
            // Ensure validator 1 was registered.
            .assert_state(
                1,
                &DoppelgangerState {
                    next_check_epoch: epoch + 1,
                    remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
                },
            )
            // Ensure validator 2 was not registered.
            .assert_unregistered(2);
    }

    enum ShouldShutdown {
        Yes,
        No,
    }

    fn get_false_responses(current_epoch: Epoch, detection_indices: &[u64]) -> LivenessResponses {
        LivenessResponses {
            current_epoch_responses: detection_indices
                .iter()
                .map(|i| LivenessResponseData {
                    index: *i as u64,
                    epoch: current_epoch,
                    is_live: false,
                })
                .collect(),
            previous_epoch_responses: detection_indices
                .iter()
                .map(|i| LivenessResponseData {
                    index: *i as u64,
                    epoch: current_epoch - 1,
                    is_live: false,
                })
                .collect(),
        }
    }

    impl TestScenario {
        pub fn simulate_detect_doppelgangers<L, F>(
            self,
            slot: Slot,
            should_shutdown: ShouldShutdown,
            get_liveness: L,
        ) -> Self
        where
            L: Fn(Epoch, Vec<u64>) -> F,
            F: Future<Output = LivenessResponses>,
        {
            // Create a simulated shutdown sender.
            let mut did_shutdown = false;
            let mut shutdown_func = || did_shutdown = true;

            // Create a simulated validator store that can resolve pubkeys to indices.
            let pubkey_to_index = self.pubkey_to_index_map();
            let get_index = |pubkey| pubkey_to_index.get(&pubkey).copied();

            block_on(self.doppelganger.detect_doppelgangers::<E, _, _, _, _>(
                slot,
                &get_index,
                &get_liveness,
                &mut shutdown_func,
            ))
            .expect("detection should not error");

            match should_shutdown {
                ShouldShutdown::Yes if !did_shutdown => panic!("vc failed to shutdown"),
                ShouldShutdown::No if did_shutdown => panic!("vc shutdown when it shouldn't"),
                _ => (),
            }

            self
        }
    }

    #[test]
    fn detect_at_genesis() {
        let epoch = genesis_epoch();
        let slot = epoch.start_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(slot)
            .register_all_in_doppelganger_protection_if_enabled()
            // All validators should have signing enabled since it's the genesis epoch.
            .assert_all_enabled()
            .simulate_detect_doppelgangers(
                slot,
                ShouldShutdown::No,
                |_, _| {
                    panic!("the beacon node should not get a request if there are no doppelganger validators");

                    // The compiler needs this, otherwise it complains that this isn't a future.
                    #[allow(unreachable_code)]
                    future::ready(get_false_responses(Epoch::new(0), &[]))
                },
            )
            // All validators should be enabled.
            .assert_all_enabled();
    }

    fn detect_after_genesis_test<F>(mutate_responses: F)
    where
        F: Fn(&mut LivenessResponses),
    {
        let starting_epoch = genesis_epoch() + 1;
        let starting_slot = starting_epoch.start_slot(E::slots_per_epoch());

        let checking_epoch = starting_epoch + 2;
        let checking_slot = checking_epoch.start_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(starting_slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled()
            // First, simulate a check where there are no doppelgangers.
            .simulate_detect_doppelgangers(
                checking_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, checking_epoch);
                    check_detection_indices(&detection_indices);

                    let liveness_responses = get_false_responses(current_epoch, &detection_indices);

                    future::ready(liveness_responses)
                },
            )
            // All validators should be disabled since they started after genesis.
            .assert_all_disabled()
            // Now, simulate a check where we apply `mutate_responses` which *must* create some
            // doppelgangers.
            .simulate_detect_doppelgangers(
                checking_slot,
                ShouldShutdown::Yes,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, checking_epoch);
                    check_detection_indices(&detection_indices);

                    let mut liveness_responses =
                        get_false_responses(current_epoch, &detection_indices);

                    mutate_responses(&mut liveness_responses);

                    future::ready(liveness_responses)
                },
            )
            // All validators should still be disabled.
            .assert_all_disabled()
            // The states of all validators should be jammed with `u64::max_value()`.
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: starting_epoch + 1,
                remaining_epochs: u64::MAX,
            });
    }

    #[test]
    fn detect_after_genesis_with_current_epoch_doppelganger() {
        detect_after_genesis_test(|liveness_responses| {
            liveness_responses.current_epoch_responses[0].is_live = true
        })
    }

    #[test]
    fn detect_after_genesis_with_previous_epoch_doppelganger() {
        detect_after_genesis_test(|liveness_responses| {
            liveness_responses.previous_epoch_responses[0].is_live = true
        })
    }

    #[test]
    fn register_prior_to_genesis() {
        let prior_to_genesis = GENESIS_TIME.checked_sub(SLOT_DURATION).unwrap();

        TestBuilder::default()
            .build()
            .set_current_time(prior_to_genesis)
            .assert_prior_to_genesis()
            .register_all_in_doppelganger_protection_if_enabled();
    }

    #[test]
    fn detect_doppelganger_in_starting_epoch() {
        let epoch = genesis_epoch() + 1;
        let slot = epoch.start_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled()
            // First, simulate a check where there is a doppelganger in the starting epoch.
            //
            // This should *not* cause a shutdown since we don't declare a doppelganger in the
            // start-up epoch to be a *real* doppelganger. Doing a fast ctrl+c and restart can cause
            // this behaviour.
            .simulate_detect_doppelgangers(
                slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, epoch);
                    check_detection_indices(&detection_indices);

                    let mut liveness_responses =
                        get_false_responses(current_epoch, &detection_indices);

                    liveness_responses.previous_epoch_responses[0].is_live = true;

                    future::ready(liveness_responses)
                },
            )
            .assert_all_disabled()
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: epoch + 1,
                remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
            });
    }

    #[test]
    fn no_doppelgangers_for_adequate_time() {
        let initial_epoch = genesis_epoch() + 42;
        let initial_slot = initial_epoch.start_slot(E::slots_per_epoch());
        let activation_slot =
            (initial_epoch + DEFAULT_REMAINING_DETECTION_EPOCHS + 1).end_slot(E::slots_per_epoch());

        let mut scenario = TestBuilder::default()
            .build()
            .set_slot(initial_slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled();

        for slot in initial_slot.as_u64()..=activation_slot.as_u64() {
            let slot = Slot::new(slot);
            let epoch = slot.epoch(E::slots_per_epoch());

            scenario = scenario.simulate_detect_doppelgangers(
                slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, epoch);
                    check_detection_indices(&detection_indices);

                    let liveness_responses = get_false_responses(current_epoch, &detection_indices);

                    future::ready(liveness_responses)
                },
            );

            let is_first_epoch = epoch == initial_epoch;
            let is_second_epoch = epoch == initial_epoch + 1;
            let is_satisfaction_slot = slot == epoch.end_slot(E::slots_per_epoch());
            let epochs_since_start = epoch.as_u64().checked_sub(initial_epoch.as_u64()).unwrap();

            let expected_state = if is_first_epoch || is_second_epoch {
                DoppelgangerState {
                    next_check_epoch: initial_epoch + 1,
                    remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
                }
            } else if !is_satisfaction_slot {
                DoppelgangerState {
                    next_check_epoch: epoch - 1,
                    remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS
                        .saturating_sub(epochs_since_start.saturating_sub(2)),
                }
            } else {
                DoppelgangerState {
                    next_check_epoch: epoch,
                    remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS
                        .saturating_sub(epochs_since_start.saturating_sub(1)),
                }
            };

            scenario = scenario.assert_all_states(&expected_state);

            scenario = if slot < activation_slot {
                scenario.assert_all_disabled()
            } else {
                scenario.assert_all_enabled()
            };
        }

        scenario
            .assert_all_enabled()
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: activation_slot.epoch(E::slots_per_epoch()),
                remaining_epochs: 0,
            });
    }

    #[test]
    fn time_skips_forward_no_doppelgangers() {
        let initial_epoch = genesis_epoch() + 1;
        let initial_slot = initial_epoch.start_slot(E::slots_per_epoch());
        let skipped_forward_epoch = initial_epoch + 42;
        let skipped_forward_slot = skipped_forward_epoch.end_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(initial_slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled()
            // First, simulate a check in the initialization epoch.
            .simulate_detect_doppelgangers(
                initial_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, initial_epoch);
                    check_detection_indices(&detection_indices);

                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            )
            .assert_all_disabled()
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: initial_epoch + 1,
                remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
            })
            // Simulate a check in the skipped forward slot
            .simulate_detect_doppelgangers(
                skipped_forward_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, skipped_forward_epoch);
                    assert!(!detection_indices.is_empty());
                    check_detection_indices(&detection_indices);

                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            )
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: skipped_forward_epoch,
                remaining_epochs: 0,
            });
    }

    #[test]
    fn time_skips_forward_with_doppelgangers() {
        let initial_epoch = genesis_epoch() + 1;
        let initial_slot = initial_epoch.start_slot(E::slots_per_epoch());
        let skipped_forward_epoch = initial_epoch + 42;
        let skipped_forward_slot = skipped_forward_epoch.end_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(initial_slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled()
            // First, simulate a check in the initialization epoch.
            .simulate_detect_doppelgangers(
                initial_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, initial_epoch);
                    check_detection_indices(&detection_indices);

                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            )
            .assert_all_disabled()
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: initial_epoch + 1,
                remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
            })
            // Simulate a check in the skipped forward slot
            .simulate_detect_doppelgangers(
                skipped_forward_slot,
                ShouldShutdown::Yes,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, skipped_forward_epoch);
                    assert!(!detection_indices.is_empty());

                    let mut liveness_responses =
                        get_false_responses(current_epoch, &detection_indices);

                    liveness_responses.previous_epoch_responses[1].is_live = true;

                    future::ready(liveness_responses)
                },
            )
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: initial_epoch + 1,
                remaining_epochs: u64::max_value(),
            });
    }

    #[test]
    fn time_skips_backward() {
        let initial_epoch = genesis_epoch() + 42;
        let initial_slot = initial_epoch.start_slot(E::slots_per_epoch());
        let skipped_backward_epoch = initial_epoch - 12;
        let skipped_backward_slot = skipped_backward_epoch.end_slot(E::slots_per_epoch());

        TestBuilder::default()
            .build()
            .set_slot(initial_slot)
            .register_all_in_doppelganger_protection_if_enabled()
            .assert_all_disabled()
            // First, simulate a check in the initialization epoch.
            .simulate_detect_doppelgangers(
                initial_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, initial_epoch);
                    check_detection_indices(&detection_indices);

                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            )
            .assert_all_disabled()
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: initial_epoch + 1,
                remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
            })
            // Simulate a check in the skipped backward slot
            .simulate_detect_doppelgangers(
                skipped_backward_slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    assert_eq!(current_epoch, skipped_backward_epoch);
                    check_detection_indices(&detection_indices);

                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            )
            .assert_all_disabled()
            // When time skips backward we should *not* allow doppelganger advancement.
            .assert_all_states(&DoppelgangerState {
                next_check_epoch: initial_epoch + 1,
                remaining_epochs: DEFAULT_REMAINING_DETECTION_EPOCHS,
            });
    }

    #[test]
    fn staggered_entry() {
        let early_epoch = genesis_epoch() + 42;
        let early_slot = early_epoch.start_slot(E::slots_per_epoch());
        let early_activation_slot =
            (early_epoch + DEFAULT_REMAINING_DETECTION_EPOCHS + 1).end_slot(E::slots_per_epoch());

        let late_epoch = early_epoch + 1;
        let late_slot = late_epoch.start_slot(E::slots_per_epoch());
        let late_activation_slot =
            (late_epoch + DEFAULT_REMAINING_DETECTION_EPOCHS + 1).end_slot(E::slots_per_epoch());

        let early_validators: Vec<u64> = (0..DEFAULT_VALIDATORS as u64 / 2).collect();
        let late_validators: Vec<u64> =
            (DEFAULT_VALIDATORS as u64 / 2..DEFAULT_VALIDATORS as u64).collect();

        let mut scenario = TestBuilder::default()
            .build()
            .set_slot(early_slot)
            .register_validators(&early_validators)
            .set_slot(late_slot)
            .register_validators(&late_validators)
            .assert_all_disabled();

        for slot in early_slot.as_u64()..=late_activation_slot.as_u64() {
            let slot = Slot::new(slot);

            scenario = scenario.simulate_detect_doppelgangers(
                slot,
                ShouldShutdown::No,
                |current_epoch, detection_indices: Vec<_>| {
                    future::ready(get_false_responses(current_epoch, &detection_indices))
                },
            );

            for index in 0..DEFAULT_VALIDATORS as u64 {
                let pubkey = *scenario.validators.get(index as usize).unwrap();

                let should_be_disabled = if early_validators.contains(&index) {
                    slot < early_activation_slot
                } else if late_validators.contains(&index) {
                    slot < late_activation_slot
                } else {
                    unreachable!("inconsistent test");
                };

                if should_be_disabled {
                    assert_eq!(
                        scenario.doppelganger.validator_status(pubkey),
                        DoppelgangerStatus::SigningDisabled(pubkey)
                    )
                } else {
                    assert_eq!(
                        scenario.doppelganger.validator_status(pubkey),
                        DoppelgangerStatus::SigningEnabled(pubkey)
                    )
                }
            }
        }

        scenario.assert_all_enabled();
    }
}
