//! The `DutiesService` contains the attester/proposer duties for all local validators.
//!
//! It learns of the local validator via the `crate::ValidatorStore` struct. It keeps the duties
//! up-to-date by polling the beacon node on regular intervals.
//!
//! The `DutiesService` is also responsible for sending events to the `BlockService` which trigger
//! block production.

mod sync;

use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{
    block_service::BlockServiceNotification,
    http_metrics::metrics,
    validator_store::{DoppelgangerStatus, Error as ValidatorStoreError, ValidatorStore},
};
use environment::RuntimeContext;
use eth2::types::{AttesterData, BeaconCommitteeSubscription, ProposerData, StateId, ValidatorId};
use futures::future::join_all;
use parking_lot::RwLock;
use safe_arith::ArithError;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sync::poll_sync_committee_duties;
use sync::SyncDutiesMap;
use tokio::{sync::mpsc::Sender, time::sleep};
use types::{ChainSpec, Epoch, EthSpec, Hash256, PublicKeyBytes, SelectionProof, Slot};

/// Since the BN does not like it when we subscribe to slots that are close to the current time, we
/// will only subscribe to slots which are further than `SUBSCRIPTION_BUFFER_SLOTS` away.
///
/// This number is based upon `MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD` value in the
/// `beacon_node::network::attestation_service` crate. It is not imported directly to avoid
/// bringing in the entire crate.
const SUBSCRIPTION_BUFFER_SLOTS: u64 = 2;

/// Only retain `HISTORICAL_DUTIES_EPOCHS` duties prior to the current epoch.
const HISTORICAL_DUTIES_EPOCHS: u64 = 2;

#[derive(Debug)]
pub enum Error {
    UnableToReadSlotClock,
    FailedToDownloadAttesters(String),
    FailedToProduceSelectionProof(ValidatorStoreError),
    InvalidModulo(ArithError),
    Arith(ArithError),
    SyncDutiesNotFound(u64),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Self::Arith(e)
    }
}

/// Neatly joins the server-generated `AttesterData` with the locally-generated `selection_proof`.
#[derive(Clone)]
pub struct DutyAndProof {
    pub duty: AttesterData,
    /// This value is only set to `Some` if the proof indicates that the validator is an aggregator.
    pub selection_proof: Option<SelectionProof>,
}

impl DutyAndProof {
    /// Instantiate `Self`, computing the selection proof as well.
    pub async fn new<T: SlotClock + 'static, E: EthSpec>(
        duty: AttesterData,
        validator_store: &ValidatorStore<T, E>,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let selection_proof = validator_store
            .produce_selection_proof(duty.pubkey, duty.slot)
            .await
            .map_err(Error::FailedToProduceSelectionProof)?;

        let selection_proof = selection_proof
            .is_aggregator(duty.committee_length as usize, spec)
            .map_err(Error::InvalidModulo)
            .map(|is_aggregator| {
                if is_aggregator {
                    Some(selection_proof)
                } else {
                    // Don't bother storing the selection proof if the validator isn't an
                    // aggregator, we won't need it.
                    None
                }
            })?;

        Ok(Self {
            duty,
            selection_proof,
        })
    }
}

/// To assist with readability, the dependent root for attester/proposer duties.
type DependentRoot = Hash256;

type AttesterMap = HashMap<PublicKeyBytes, HashMap<Epoch, (DependentRoot, DutyAndProof)>>;
type ProposerMap = HashMap<Epoch, (DependentRoot, Vec<ProposerData>)>;

/// See the module-level documentation.
pub struct DutiesService<T, E: EthSpec> {
    /// Maps a validator public key to their duties for each epoch.
    pub attesters: RwLock<AttesterMap>,
    /// Maps an epoch to all *local* proposers in this epoch. Notably, this does not contain
    /// proposals for any validators which are not registered locally.
    pub proposers: RwLock<ProposerMap>,
    /// Map from validator index to sync committee duties.
    pub sync_duties: SyncDutiesMap,
    /// Provides the canonical list of locally-managed validators.
    pub validator_store: Arc<ValidatorStore<T, E>>,
    /// Tracks the current slot.
    pub slot_clock: T,
    /// Provides HTTP access to remote beacon nodes.
    pub beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    /// Controls whether or not this function will refuse to interact with non-synced beacon nodes.
    ///
    /// This functionality is a little redundant since most BNs will likely reject duties when they
    /// aren't synced, but we keep it around for an emergency.
    pub require_synced: RequireSynced,
    pub context: RuntimeContext<E>,
    pub spec: ChainSpec,
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesService<T, E> {
    /// Returns the total number of validators known to the duties service.
    pub fn total_validator_count(&self) -> usize {
        self.validator_store.num_voting_validators()
    }

    /// Returns the total number of validators that should propose in the given epoch.
    pub fn proposer_count(&self, epoch: Epoch) -> usize {
        // Only collect validators that are considered safe in terms of doppelganger protection.
        let signing_pubkeys: HashSet<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);

        self.proposers
            .read()
            .get(&epoch)
            .map_or(0, |(_, proposers)| {
                proposers
                    .iter()
                    .filter(|proposer_data| signing_pubkeys.contains(&proposer_data.pubkey))
                    .count()
            })
    }

    /// Returns the total number of validators that should attest in the given epoch.
    pub fn attester_count(&self, epoch: Epoch) -> usize {
        // Only collect validators that are considered safe in terms of doppelganger protection.
        let signing_pubkeys: HashSet<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);
        self.attesters
            .read()
            .iter()
            .filter_map(|(_, map)| map.get(&epoch))
            .map(|(_, duty_and_proof)| duty_and_proof)
            .filter(|duty_and_proof| signing_pubkeys.contains(&duty_and_proof.duty.pubkey))
            .count()
    }

    /// Returns the total number of validators that are in a doppelganger detection period.
    pub fn doppelganger_detecting_count(&self) -> usize {
        self.validator_store
            .voting_pubkeys::<HashSet<_>, _>(DoppelgangerStatus::only_unsafe)
            .len()
    }

    /// Returns the pubkeys of the validators which are assigned to propose in the given slot.
    ///
    /// It is possible that multiple validators have an identical proposal slot, however that is
    /// likely the result of heavy forking (lol) or inconsistent beacon node connections.
    pub fn block_proposers(&self, slot: Slot) -> HashSet<PublicKeyBytes> {
        let epoch = slot.epoch(E::slots_per_epoch());

        // Only collect validators that are considered safe in terms of doppelganger protection.
        let signing_pubkeys: HashSet<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);

        self.proposers
            .read()
            .get(&epoch)
            .map(|(_, proposers)| {
                proposers
                    .iter()
                    .filter(|proposer_data| {
                        proposer_data.slot == slot
                            && signing_pubkeys.contains(&proposer_data.pubkey)
                    })
                    .map(|proposer_data| proposer_data.pubkey)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all `ValidatorDuty` for the given `slot`.
    pub fn attesters(&self, slot: Slot) -> Vec<DutyAndProof> {
        let epoch = slot.epoch(E::slots_per_epoch());

        // Only collect validators that are considered safe in terms of doppelganger protection.
        let signing_pubkeys: HashSet<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);

        self.attesters
            .read()
            .iter()
            .filter_map(|(_, map)| map.get(&epoch))
            .map(|(_, duty_and_proof)| duty_and_proof)
            .filter(|duty_and_proof| {
                duty_and_proof.duty.slot == slot
                    && signing_pubkeys.contains(&duty_and_proof.duty.pubkey)
            })
            .cloned()
            .collect()
    }
}

/// Start the service that periodically polls the beacon node for validator duties. This will start
/// several sub-services.
///
/// ## Notes
///
/// The loops in this function are structured such that a new instance of that task will only start
/// once the current one is finished. This means that if a task happens to take more than one slot
/// to run, we might skip a slot. This is unfortunate, however the alternative is to *always*
/// process every slot, which has the chance of creating a theoretically unlimited backlog of tasks.
/// It was a conscious decision to choose to drop tasks on an overloaded/latent system rather than
/// overload it even more.
pub fn start_update_service<T: SlotClock + 'static, E: EthSpec>(
    core_duties_service: Arc<DutiesService<T, E>>,
    mut block_service_tx: Sender<BlockServiceNotification>,
) {
    /*
     * Spawn the task which updates the map of pubkey to validator index.
     */
    let duties_service = core_duties_service.clone();
    core_duties_service.context.executor.spawn(
        async move {
            loop {
                // Run this poll before the wait, this should hopefully download all the indices
                // before the block/attestation tasks need them.
                poll_validator_indices(&duties_service).await;

                if let Some(duration) = duties_service.slot_clock.duration_to_next_slot() {
                    sleep(duration).await;
                } else {
                    // Just sleep for one slot if we are unable to read the system clock, this gives
                    // us an opportunity for the clock to eventually come good.
                    sleep(duties_service.slot_clock.slot_duration()).await;
                }
            }
        },
        "duties_service_indices",
    );

    /*
     * Spawn the task which keeps track of local block proposal duties.
     */
    let duties_service = core_duties_service.clone();
    let log = core_duties_service.context.log().clone();
    core_duties_service.context.executor.spawn(
        async move {
            loop {
                if let Some(duration) = duties_service.slot_clock.duration_to_next_slot() {
                    sleep(duration).await;
                } else {
                    // Just sleep for one slot if we are unable to read the system clock, this gives
                    // us an opportunity for the clock to eventually come good.
                    sleep(duties_service.slot_clock.slot_duration()).await;
                    continue;
                }

                if let Err(e) = poll_beacon_proposers(&duties_service, &mut block_service_tx).await
                {
                    error!(
                       log,
                       "Failed to poll beacon proposers";
                       "error" => ?e
                    )
                }
            }
        },
        "duties_service_proposers",
    );

    /*
     * Spawn the task which keeps track of local attestation duties.
     */
    let duties_service = core_duties_service.clone();
    let log = core_duties_service.context.log().clone();
    core_duties_service.context.executor.spawn(
        async move {
            loop {
                if let Some(duration) = duties_service.slot_clock.duration_to_next_slot() {
                    sleep(duration).await;
                } else {
                    // Just sleep for one slot if we are unable to read the system clock, this gives
                    // us an opportunity for the clock to eventually come good.
                    sleep(duties_service.slot_clock.slot_duration()).await;
                    continue;
                }

                if let Err(e) = poll_beacon_attesters(&duties_service).await {
                    error!(
                       log,
                       "Failed to poll beacon attesters";
                       "error" => ?e
                    );
                }
            }
        },
        "duties_service_attesters",
    );

    // Spawn the task which keeps track of local sync committee duties.
    let duties_service = core_duties_service.clone();
    let log = core_duties_service.context.log().clone();
    core_duties_service.context.executor.spawn(
        async move {
            loop {
                if let Err(e) = poll_sync_committee_duties(&duties_service).await {
                    error!(
                       log,
                       "Failed to poll sync committee duties";
                       "error" => ?e
                    );
                }

                // Wait until the next slot before polling again.
                // This doesn't mean that the beacon node will get polled every slot
                // as the sync duties service will return early if it deems it already has
                // enough information.
                if let Some(duration) = duties_service.slot_clock.duration_to_next_slot() {
                    sleep(duration).await;
                } else {
                    // Just sleep for one slot if we are unable to read the system clock, this gives
                    // us an opportunity for the clock to eventually come good.
                    sleep(duties_service.slot_clock.slot_duration()).await;
                    continue;
                }
            }
        },
        "duties_service_sync_committee",
    );
}

/// Iterate through all the voting pubkeys in the `ValidatorStore` and attempt to learn any unknown
/// validator indices.
async fn poll_validator_indices<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
) {
    let _timer =
        metrics::start_timer_vec(&metrics::DUTIES_SERVICE_TIMES, &[metrics::UPDATE_INDICES]);

    let log = duties_service.context.log();

    // Collect *all* pubkeys for resolving indices, even those undergoing doppelganger protection.
    //
    // Since doppelganger protection queries rely on validator indices it is important to ensure we
    // collect those indices.
    let all_pubkeys: Vec<_> = duties_service
        .validator_store
        .voting_pubkeys(DoppelgangerStatus::ignored);

    for pubkey in all_pubkeys {
        // This is on its own line to avoid some weirdness with locks and if statements.
        let is_known = duties_service
            .validator_store
            .initialized_validators()
            .read()
            .get_index(&pubkey)
            .is_some();

        if !is_known {
            // Query the remote BN to resolve a pubkey to a validator index.
            let download_result = duties_service
                .beacon_nodes
                .first_success(duties_service.require_synced, |beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::DUTIES_SERVICE_TIMES,
                        &[metrics::VALIDATOR_ID_HTTP_GET],
                    );
                    beacon_node
                        .get_beacon_states_validator_id(
                            StateId::Head,
                            &ValidatorId::PublicKey(pubkey),
                        )
                        .await
                })
                .await;

            match download_result {
                Ok(Some(response)) => {
                    info!(
                        log,
                        "Validator exists in beacon chain";
                        "pubkey" => ?pubkey,
                        "validator_index" => response.data.index
                    );
                    duties_service
                        .validator_store
                        .initialized_validators()
                        .write()
                        .set_index(&pubkey, response.data.index);
                }
                // This is not necessarily an error, it just means the validator is not yet known to
                // the beacon chain.
                Ok(None) => {
                    debug!(
                        log,
                        "Validator without index";
                        "pubkey" => ?pubkey
                    )
                }
                // Don't exit early on an error, keep attempting to resolve other indices.
                Err(e) => {
                    error!(
                        log,
                        "Failed to resolve pubkey to index";
                        "error" => %e,
                        "pubkey" => ?pubkey,
                    )
                }
            }
        }
    }
}

/// Query the beacon node for attestation duties for any known validators.
///
/// This function will perform (in the following order):
///
/// 1. Poll for current-epoch duties and update the local `duties_service.attesters` map.
/// 2. As above, but for the next-epoch.
/// 3. Push out any attestation subnet subscriptions to the BN.
/// 4. Prune old entries from `duties_service.attesters`.
async fn poll_beacon_attesters<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
) -> Result<(), Error> {
    let current_epoch_timer = metrics::start_timer_vec(
        &metrics::DUTIES_SERVICE_TIMES,
        &[metrics::UPDATE_ATTESTERS_CURRENT_EPOCH],
    );

    let log = duties_service.context.log();

    let current_slot = duties_service
        .slot_clock
        .now()
        .ok_or(Error::UnableToReadSlotClock)?;
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    let next_epoch = current_epoch + 1;

    // Collect *all* pubkeys, even those undergoing doppelganger protection.
    //
    // We must know the duties for doppelganger validators so that we can subscribe to their subnets
    // and get more information about other running instances.
    let local_pubkeys: HashSet<_> = duties_service
        .validator_store
        .voting_pubkeys(DoppelgangerStatus::ignored);

    let local_indices = {
        let mut local_indices = Vec::with_capacity(local_pubkeys.len());

        let vals_ref = duties_service.validator_store.initialized_validators();
        let vals = vals_ref.read();
        for &pubkey in &local_pubkeys {
            if let Some(validator_index) = vals.get_index(&pubkey) {
                local_indices.push(validator_index)
            }
        }
        local_indices
    };

    // Download the duties and update the duties for the current epoch.
    if let Err(e) = poll_beacon_attesters_for_epoch(
        duties_service,
        current_epoch,
        &local_indices,
        &local_pubkeys,
    )
    .await
    {
        error!(
            log,
            "Failed to download attester duties";
            "current_epoch" => current_epoch,
            "request_epoch" => current_epoch,
            "err" => ?e,
        )
    }

    drop(current_epoch_timer);
    let next_epoch_timer = metrics::start_timer_vec(
        &metrics::DUTIES_SERVICE_TIMES,
        &[metrics::UPDATE_ATTESTERS_NEXT_EPOCH],
    );

    // Download the duties and update the duties for the next epoch.
    if let Err(e) =
        poll_beacon_attesters_for_epoch(duties_service, next_epoch, &local_indices, &local_pubkeys)
            .await
    {
        error!(
            log,
            "Failed to download attester duties";
            "current_epoch" => current_epoch,
            "request_epoch" => next_epoch,
            "err" => ?e,
        )
    }

    drop(next_epoch_timer);
    let subscriptions_timer =
        metrics::start_timer_vec(&metrics::DUTIES_SERVICE_TIMES, &[metrics::SUBSCRIPTIONS]);

    // This vector is likely to be a little oversized, but it won't reallocate.
    let mut subscriptions = Vec::with_capacity(local_pubkeys.len() * 2);

    // For this epoch and the next epoch, produce any beacon committee subscriptions.
    //
    // We are *always* pushing out subscriptions, even if we've subscribed before. This is
    // potentially excessive on the BN in normal cases, but it will help with fast re-subscriptions
    // if the BN goes offline or we swap to a different one.
    for epoch in &[current_epoch, next_epoch] {
        duties_service
            .attesters
            .read()
            .iter()
            .filter_map(|(_, map)| map.get(epoch))
            // The BN logs a warning if we try and subscribe to current or near-by slots. Give it a
            // buffer.
            .filter(|(_, duty_and_proof)| {
                current_slot + SUBSCRIPTION_BUFFER_SLOTS < duty_and_proof.duty.slot
            })
            .for_each(|(_, duty_and_proof)| {
                let duty = &duty_and_proof.duty;
                let is_aggregator = duty_and_proof.selection_proof.is_some();

                subscriptions.push(BeaconCommitteeSubscription {
                    validator_index: duty.validator_index,
                    committee_index: duty.committee_index,
                    committees_at_slot: duty.committees_at_slot,
                    slot: duty.slot,
                    is_aggregator,
                })
            });
    }

    // If there are any subscriptions, push them out to the beacon node.
    if !subscriptions.is_empty() {
        let subscriptions_ref = &subscriptions;
        if let Err(e) = duties_service
            .beacon_nodes
            .first_success(duties_service.require_synced, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::DUTIES_SERVICE_TIMES,
                    &[metrics::SUBSCRIPTIONS_HTTP_POST],
                );
                beacon_node
                    .post_validator_beacon_committee_subscriptions(subscriptions_ref)
                    .await
            })
            .await
        {
            error!(
                log,
                "Failed to subscribe validators";
                "error" => %e
            )
        }
    }

    drop(subscriptions_timer);

    // Prune old duties.
    duties_service
        .attesters
        .write()
        .iter_mut()
        .for_each(|(_, map)| {
            map.retain(|&epoch, _| epoch + HISTORICAL_DUTIES_EPOCHS >= current_epoch)
        });

    Ok(())
}

/// For the given `local_indices` and `local_pubkeys`, download the duties for the given `epoch` and
/// store them in `duties_service.attesters`.
async fn poll_beacon_attesters_for_epoch<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
    epoch: Epoch,
    local_indices: &[u64],
    local_pubkeys: &HashSet<PublicKeyBytes>,
) -> Result<(), Error> {
    let log = duties_service.context.log();

    // No need to bother the BN if we don't have any validators.
    if local_indices.is_empty() {
        debug!(
            duties_service.context.log(),
            "No validators, not downloading duties";
            "epoch" => epoch,
        );
        return Ok(());
    }

    let fetch_timer = metrics::start_timer_vec(
        &metrics::DUTIES_SERVICE_TIMES,
        &[metrics::UPDATE_ATTESTERS_FETCH],
    );

    let response = duties_service
        .beacon_nodes
        .first_success(duties_service.require_synced, |beacon_node| async move {
            let _timer = metrics::start_timer_vec(
                &metrics::DUTIES_SERVICE_TIMES,
                &[metrics::ATTESTER_DUTIES_HTTP_POST],
            );
            beacon_node
                .post_validator_duties_attester(epoch, local_indices)
                .await
        })
        .await
        .map_err(|e| Error::FailedToDownloadAttesters(e.to_string()))?;

    drop(fetch_timer);
    let _store_timer = metrics::start_timer_vec(
        &metrics::DUTIES_SERVICE_TIMES,
        &[metrics::UPDATE_ATTESTERS_STORE],
    );

    let dependent_root = response.dependent_root;

    // Filter any duties that are not relevant or already known.
    let new_duties = {
        // Avoid holding the read-lock for any longer than required.
        let attesters = duties_service.attesters.read();
        response
            .data
            .into_iter()
            .filter(|duty| local_pubkeys.contains(&duty.pubkey))
            .filter(|duty| {
                // Only update the duties if either is true:
                //
                // - There were no known duties for this epoch.
                // - The dependent root has changed, signalling a re-org.
                attesters.get(&duty.pubkey).map_or(true, |duties| {
                    duties
                        .get(&epoch)
                        .map_or(true, |(prior, _)| *prior != dependent_root)
                })
            })
            .collect::<Vec<_>>()
    };

    debug!(
        log,
        "Downloaded attester duties";
        "dependent_root" => %dependent_root,
        "num_new_duties" => new_duties.len(),
    );

    // Produce the `DutyAndProof` messages in parallel.
    let duty_and_proof_results = join_all(new_duties.into_iter().map(|duty| {
        DutyAndProof::new(duty, &duties_service.validator_store, &duties_service.spec)
    }))
    .await;

    // Update the duties service with the new `DutyAndProof` messages.
    let mut attesters = duties_service.attesters.write();
    let mut already_warned = Some(());
    for result in duty_and_proof_results {
        let duty_and_proof = match result {
            Ok(duty_and_proof) => duty_and_proof,
            Err(e) => {
                error!(
                    log,
                    "Failed to produce duty and proof";
                    "error" => ?e,
                    "msg" => "may impair attestation duties"
                );
                // Do not abort the entire batch for a single failure.
                continue;
            }
        };

        let attester_map = attesters.entry(duty_and_proof.duty.pubkey).or_default();

        if let Some((prior_dependent_root, _)) =
            attester_map.insert(epoch, (dependent_root, duty_and_proof))
        {
            // Using `already_warned` avoids excessive logs.
            if dependent_root != prior_dependent_root && already_warned.take().is_some() {
                warn!(
                    log,
                    "Attester duties re-org";
                    "prior_dependent_root" => %prior_dependent_root,
                    "dependent_root" => %dependent_root,
                    "msg" => "this may happen from time to time"
                )
            }
        }
    }
    drop(attesters);

    Ok(())
}

/// Download the proposer duties for the current epoch and store them in `duties_service.proposers`.
/// If there are any proposer for this slot, send out a notification to the block proposers.
///
/// ## Note
///
/// This function will potentially send *two* notifications to the `BlockService`; it will send a
/// notification initially, then it will download the latest duties and send a *second* notification
/// if those duties have changed. This behaviour simultaneously achieves the following:
///
/// 1. Block production can happen immediately and does not have to wait for the proposer duties to
///    download.
/// 2. We won't miss a block if the duties for the current slot happen to change with this poll.
///
/// This sounds great, but is it safe? Firstly, the additional notification will only contain block
/// producers that were not included in the first notification. This should be safety enough.
/// However, we also have the slashing protection as a second line of defence. These two factors
/// provide an acceptable level of safety.
///
/// It's important to note that since there is a 0-epoch look-ahead (i.e., no look-ahead) for block
/// proposers then it's very likely that a proposal for the first slot of the epoch will need go
/// through the slow path every time. I.e., the proposal will only happen after we've been able to
/// download and process the duties from the BN. This means it is very important to ensure this
/// function is as fast as possible.
async fn poll_beacon_proposers<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
    block_service_tx: &mut Sender<BlockServiceNotification>,
) -> Result<(), Error> {
    let _timer =
        metrics::start_timer_vec(&metrics::DUTIES_SERVICE_TIMES, &[metrics::UPDATE_PROPOSERS]);

    let log = duties_service.context.log();

    let current_slot = duties_service
        .slot_clock
        .now()
        .ok_or(Error::UnableToReadSlotClock)?;
    let current_epoch = current_slot.epoch(E::slots_per_epoch());

    // Notify the block proposal service for any proposals that we have in our cache.
    //
    // See the function-level documentation for more information.
    let initial_block_proposers = duties_service.block_proposers(current_slot);
    notify_block_production_service(
        current_slot,
        &initial_block_proposers,
        block_service_tx,
        &duties_service.validator_store,
        log,
    )
    .await;

    // Collect *all* pubkeys, even those undergoing doppelganger protection.
    //
    // It is useful to keep the duties for all validators around, so they're on hand when
    // doppelganger finishes.
    let local_pubkeys: HashSet<_> = duties_service
        .validator_store
        .voting_pubkeys(DoppelgangerStatus::ignored);

    // Only download duties and push out additional block production events if we have some
    // validators.
    if !local_pubkeys.is_empty() {
        let download_result = duties_service
            .beacon_nodes
            .first_success(duties_service.require_synced, |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::DUTIES_SERVICE_TIMES,
                    &[metrics::PROPOSER_DUTIES_HTTP_GET],
                );
                beacon_node
                    .get_validator_duties_proposer(current_epoch)
                    .await
            })
            .await;

        match download_result {
            Ok(response) => {
                let dependent_root = response.dependent_root;

                let relevant_duties = response
                    .data
                    .into_iter()
                    .filter(|proposer_duty| local_pubkeys.contains(&proposer_duty.pubkey))
                    .collect::<Vec<_>>();

                debug!(
                    log,
                    "Downloaded proposer duties";
                    "dependent_root" => %dependent_root,
                    "num_relevant_duties" => relevant_duties.len(),
                );

                if let Some((prior_dependent_root, _)) = duties_service
                    .proposers
                    .write()
                    .insert(current_epoch, (dependent_root, relevant_duties))
                {
                    if dependent_root != prior_dependent_root {
                        warn!(
                            log,
                            "Proposer duties re-org";
                            "prior_dependent_root" => %prior_dependent_root,
                            "dependent_root" => %dependent_root,
                            "msg" => "this may happen from time to time"
                        )
                    }
                }
            }
            // Don't return early here, we still want to try and produce blocks using the cached values.
            Err(e) => error!(
                log,
                "Failed to download proposer duties";
                "err" => %e,
            ),
        }

        // Compute the block proposers for this slot again, now that we've received an update from
        // the BN.
        //
        // Then, compute the difference between these two sets to obtain a set of block proposers
        // which were not included in the initial notification to the `BlockService`.
        let additional_block_producers = duties_service
            .block_proposers(current_slot)
            .difference(&initial_block_proposers)
            .copied()
            .collect::<HashSet<PublicKeyBytes>>();

        // If there are any new proposers for this slot, send a notification so they produce a
        // block.
        //
        // See the function-level documentation for more reasoning about this behaviour.
        if !additional_block_producers.is_empty() {
            notify_block_production_service(
                current_slot,
                &additional_block_producers,
                block_service_tx,
                &duties_service.validator_store,
                log,
            )
            .await;
            debug!(
                log,
                "Detected new block proposer";
                "current_slot" => current_slot,
            );
            metrics::inc_counter(&metrics::PROPOSAL_CHANGED);
        }
    }

    // Prune old duties.
    duties_service
        .proposers
        .write()
        .retain(|&epoch, _| epoch + HISTORICAL_DUTIES_EPOCHS >= current_epoch);

    Ok(())
}

/// Notify the block service if it should produce a block.
async fn notify_block_production_service<T: SlotClock + 'static, E: EthSpec>(
    current_slot: Slot,
    block_proposers: &HashSet<PublicKeyBytes>,
    block_service_tx: &mut Sender<BlockServiceNotification>,
    validator_store: &ValidatorStore<T, E>,
    log: &Logger,
) {
    let non_doppelganger_proposers = block_proposers
        .iter()
        .filter(|pubkey| validator_store.doppelganger_protection_allows_signing(**pubkey))
        .copied()
        .collect::<Vec<_>>();

    if !non_doppelganger_proposers.is_empty() {
        if let Err(e) = block_service_tx
            .send(BlockServiceNotification {
                slot: current_slot,
                block_proposers: non_doppelganger_proposers,
            })
            .await
        {
            error!(
                log,
                "Failed to notify block service";
                "current_slot" => current_slot,
                "error" => %e
            );
        };
    }
}
