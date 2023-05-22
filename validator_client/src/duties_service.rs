//! The `DutiesService` contains the attester/proposer duties for all local validators.
//!
//! It learns of the local validator via the `crate::ValidatorStore` struct. It keeps the duties
//! up-to-date by polling the beacon node on regular intervals.
//!
//! The `DutiesService` is also responsible for sending events to the `BlockService` which trigger
//! block production.

mod sync;

use crate::beacon_node_fallback::{BeaconNodeFallback, OfflineOnFailure, RequireSynced};
use crate::http_metrics::metrics::{get_int_gauge, set_int_gauge, ATTESTATION_DUTY};
use crate::{
    block_service::BlockServiceNotification,
    http_metrics::metrics,
    validator_store::{DoppelgangerStatus, Error as ValidatorStoreError, ValidatorStore},
};
use environment::RuntimeContext;
use eth2::types::{
    AttesterData, BeaconCommitteeSubscription, DutiesResponse, ProposerData, StateId, ValidatorId,
};
use futures::{stream, StreamExt};
use parking_lot::RwLock;
use safe_arith::ArithError;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::cmp::min;
use std::collections::{hash_map, BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
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

/// Compute attestation selection proofs this many slots before they are required.
///
/// At start-up selection proofs will be computed with less lookahead out of necessity.
const SELECTION_PROOF_SLOT_LOOKAHEAD: u64 = 8;

/// Fraction of a slot at which selection proof signing should happen (2 means half way).
const SELECTION_PROOF_SCHEDULE_DENOM: u32 = 2;

/// Minimum number of validators for which we auto-enable per-validator metrics.
/// For validators greater than this value, we need to manually set the `enable-per-validator-metrics`
/// flag in the cli to enable collection of per validator metrics.
const VALIDATOR_METRICS_MIN_COUNT: usize = 64;

/// The number of validators to request duty information for in the initial request.
/// The initial request is used to determine if further requests are required, so that it
/// reduces the amount of data that needs to be transferred.
const INITIAL_DUTIES_QUERY_SIZE: usize = 1;

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
    pub async fn new_with_selection_proof<T: SlotClock + 'static, E: EthSpec>(
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

    /// Create a new `DutyAndProof` with the selection proof waiting to be filled in.
    pub fn new_without_selection_proof(duty: AttesterData) -> Self {
        Self {
            duty,
            selection_proof: None,
        }
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
    pub enable_high_validator_count_metrics: bool,
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

    /// Returns `true` if we should collect per validator metrics and `false` otherwise.
    pub fn per_validator_metrics(&self) -> bool {
        self.enable_high_validator_count_metrics
            || self.total_validator_count() <= VALIDATOR_METRICS_MIN_COUNT
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
                .first_success(
                    RequireSynced::No,
                    OfflineOnFailure::Yes,
                    |beacon_node| async move {
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
                    },
                )
                .await;

            let fee_recipient = duties_service
                .validator_store
                .get_fee_recipient(&pubkey)
                .map(|fr| fr.to_string())
                .unwrap_or_else(|| {
                    "Fee recipient for validator not set in validator_definitions.yml \
                    or provided with the `--suggested-fee-recipient` flag"
                        .to_string()
                });
            match download_result {
                Ok(Some(response)) => {
                    info!(
                        log,
                        "Validator exists in beacon chain";
                        "pubkey" => ?pubkey,
                        "validator_index" => response.data.index,
                        "fee_recipient" => fee_recipient
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
                        "pubkey" => ?pubkey,
                        "fee_recipient" => fee_recipient
                    )
                }
                // Don't exit early on an error, keep attempting to resolve other indices.
                Err(e) => {
                    error!(
                        log,
                        "Failed to resolve pubkey to index";
                        "error" => %e,
                        "pubkey" => ?pubkey,
                        "fee_recipient" => fee_recipient
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
    duties_service: &Arc<DutiesService<T, E>>,
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

    update_per_validator_duty_metrics::<T, E>(duties_service, current_epoch, current_slot);

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

    update_per_validator_duty_metrics::<T, E>(duties_service, next_epoch, current_slot);

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

    // If there are any subscriptions, push them out to beacon nodes
    if !subscriptions.is_empty() {
        let subscriptions_ref = &subscriptions;
        if let Err(e) = duties_service
            .beacon_nodes
            .run(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::DUTIES_SERVICE_TIMES,
                        &[metrics::SUBSCRIPTIONS_HTTP_POST],
                    );
                    beacon_node
                        .post_validator_beacon_committee_subscriptions(subscriptions_ref)
                        .await
                },
            )
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
    duties_service: &Arc<DutiesService<T, E>>,
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

    // Request duties for all uninitialized validators. If there isn't any, we will just request for
    // `INITIAL_DUTIES_QUERY_SIZE` validators. We use the `dependent_root` in the response to
    // determine whether validator duties need to be updated. This is to ensure that we don't
    // request for extra data unless necessary in order to save on network bandwidth.
    let uninitialized_validators =
        get_uninitialized_validators(duties_service, &epoch, local_pubkeys);
    let indices_to_request = if !uninitialized_validators.is_empty() {
        uninitialized_validators.as_slice()
    } else {
        &local_indices[0..min(INITIAL_DUTIES_QUERY_SIZE, local_indices.len())]
    };

    let response =
        post_validator_duties_attester(duties_service, epoch, indices_to_request).await?;
    let dependent_root = response.dependent_root;

    // Find any validators which have conflicting (epoch, dependent_root) values or missing duties for the epoch.
    let validators_to_update: Vec<_> = {
        // Avoid holding the read-lock for any longer than required.
        let attesters = duties_service.attesters.read();
        local_pubkeys
            .iter()
            .filter(|pubkey| {
                attesters.get(pubkey).map_or(true, |duties| {
                    duties
                        .get(&epoch)
                        .map_or(true, |(prior, _)| *prior != dependent_root)
                })
            })
            .collect::<Vec<_>>()
    };

    if validators_to_update.is_empty() {
        // No validators have conflicting (epoch, dependent_root) values or missing duties for the epoch.
        return Ok(());
    }

    // Filter out validators which have already been requested.
    let initial_duties = &response.data;
    let indices_to_request = validators_to_update
        .iter()
        .filter(|&&&pubkey| !initial_duties.iter().any(|duty| duty.pubkey == pubkey))
        .filter_map(|pubkey| duties_service.validator_store.validator_index(pubkey))
        .collect::<Vec<_>>();

    let new_duties = if !indices_to_request.is_empty() {
        post_validator_duties_attester(duties_service, epoch, indices_to_request.as_slice())
            .await?
            .data
            .into_iter()
            .chain(response.data)
            .collect::<Vec<_>>()
    } else {
        response.data
    };

    drop(fetch_timer);

    let _store_timer = metrics::start_timer_vec(
        &metrics::DUTIES_SERVICE_TIMES,
        &[metrics::UPDATE_ATTESTERS_STORE],
    );

    debug!(
        log,
        "Downloaded attester duties";
        "dependent_root" => %dependent_root,
        "num_new_duties" => new_duties.len(),
    );

    // Update the duties service with the new `DutyAndProof` messages.
    let mut attesters = duties_service.attesters.write();
    let mut already_warned = Some(());
    for duty in &new_duties {
        let attester_map = attesters.entry(duty.pubkey).or_default();

        // Create initial entries in the map without selection proofs. We'll compute them in the
        // background later to avoid creating a thundering herd of signing threads whenever new
        // duties are computed.
        let duty_and_proof = DutyAndProof::new_without_selection_proof(duty.clone());

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

    // Spawn the background task to compute selection proofs.
    let subservice = duties_service.clone();
    duties_service.context.executor.spawn(
        async move {
            fill_in_selection_proofs(subservice, new_duties, dependent_root).await;
        },
        "duties_service_selection_proofs_background",
    );

    Ok(())
}

/// Get a filtered list of local validators for which we don't already know their duties for that epoch
fn get_uninitialized_validators<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &Arc<DutiesService<T, E>>,
    epoch: &Epoch,
    local_pubkeys: &HashSet<PublicKeyBytes>,
) -> Vec<u64> {
    let attesters = duties_service.attesters.read();
    local_pubkeys
        .iter()
        .filter(|pubkey| {
            attesters
                .get(pubkey)
                .map_or(true, |duties| !duties.contains_key(epoch))
        })
        .filter_map(|pubkey| duties_service.validator_store.validator_index(pubkey))
        .collect::<Vec<_>>()
}

fn update_per_validator_duty_metrics<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &Arc<DutiesService<T, E>>,
    epoch: Epoch,
    current_slot: Slot,
) {
    if duties_service.per_validator_metrics() {
        let attesters = duties_service.attesters.read();
        attesters.values().for_each(|attester_duties_by_epoch| {
            if let Some((_, duty_and_proof)) = attester_duties_by_epoch.get(&epoch) {
                let duty = &duty_and_proof.duty;
                let validator_index = duty.validator_index;
                let duty_slot = duty.slot;
                if let Some(existing_slot_gauge) =
                    get_int_gauge(&ATTESTATION_DUTY, &[&validator_index.to_string()])
                {
                    let existing_slot = Slot::new(existing_slot_gauge.get() as u64);
                    let existing_epoch = existing_slot.epoch(E::slots_per_epoch());

                    // First condition ensures that we switch to the next epoch duty slot
                    // once the current epoch duty slot passes.
                    // Second condition is to ensure that next epoch duties don't override
                    // current epoch duties.
                    if existing_slot < current_slot
                        || (duty_slot.epoch(E::slots_per_epoch()) <= existing_epoch
                            && duty_slot > current_slot
                            && duty_slot != existing_slot)
                    {
                        existing_slot_gauge.set(duty_slot.as_u64() as i64);
                    }
                } else {
                    set_int_gauge(
                        &ATTESTATION_DUTY,
                        &[&validator_index.to_string()],
                        duty_slot.as_u64() as i64,
                    );
                }
            }
        });
    }
}

async fn post_validator_duties_attester<T: SlotClock + 'static, E: EthSpec>(
    duties_service: &Arc<DutiesService<T, E>>,
    epoch: Epoch,
    validator_indices: &[u64],
) -> Result<DutiesResponse<Vec<AttesterData>>, Error> {
    duties_service
        .beacon_nodes
        .first_success(
            RequireSynced::No,
            OfflineOnFailure::Yes,
            |beacon_node| async move {
                let _timer = metrics::start_timer_vec(
                    &metrics::DUTIES_SERVICE_TIMES,
                    &[metrics::ATTESTER_DUTIES_HTTP_POST],
                );
                beacon_node
                    .post_validator_duties_attester(epoch, validator_indices)
                    .await
            },
        )
        .await
        .map_err(|e| Error::FailedToDownloadAttesters(e.to_string()))
}

/// Compute the attestation selection proofs for the `duties` and add them to the `attesters` map.
///
/// Duties are computed in batches each slot. If a re-org is detected then the process will
/// terminate early as it is assumed the selection proofs from `duties` are no longer relevant.
async fn fill_in_selection_proofs<T: SlotClock + 'static, E: EthSpec>(
    duties_service: Arc<DutiesService<T, E>>,
    duties: Vec<AttesterData>,
    dependent_root: Hash256,
) {
    let log = duties_service.context.log();

    // Sort duties by slot in a BTreeMap.
    let mut duties_by_slot: BTreeMap<Slot, Vec<_>> = BTreeMap::new();

    for duty in duties {
        duties_by_slot.entry(duty.slot).or_default().push(duty);
    }

    // At halfway through each slot when nothing else is likely to be getting signed, sign a batch
    // of selection proofs and insert them into the duties service `attesters` map.
    let slot_clock = &duties_service.slot_clock;
    let slot_offset = duties_service.slot_clock.slot_duration() / SELECTION_PROOF_SCHEDULE_DENOM;

    while !duties_by_slot.is_empty() {
        if let Some(duration) = slot_clock.duration_to_next_slot() {
            sleep(duration.saturating_sub(slot_offset)).await;

            let Some(current_slot) = slot_clock.now() else {
                continue;
            };

            let lookahead_slot = current_slot + SELECTION_PROOF_SLOT_LOOKAHEAD;

            let mut relevant_duties = duties_by_slot.split_off(&lookahead_slot);
            std::mem::swap(&mut relevant_duties, &mut duties_by_slot);

            let batch_size = relevant_duties.values().map(Vec::len).sum::<usize>();

            if batch_size == 0 {
                continue;
            }

            let timer = metrics::start_timer_vec(
                &metrics::DUTIES_SERVICE_TIMES,
                &[metrics::ATTESTATION_SELECTION_PROOFS],
            );

            // Sign selection proofs (serially).
            let duty_and_proof_results = stream::iter(relevant_duties.into_values().flatten())
                .then(|duty| async {
                    DutyAndProof::new_with_selection_proof(
                        duty,
                        &duties_service.validator_store,
                        &duties_service.spec,
                    )
                    .await
                })
                .collect::<Vec<_>>()
                .await;

            // Add to attesters store.
            let mut attesters = duties_service.attesters.write();
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
                let epoch = duty_and_proof.duty.slot.epoch(E::slots_per_epoch());
                match attester_map.entry(epoch) {
                    hash_map::Entry::Occupied(mut entry) => {
                        // No need to update duties for which no proof was computed.
                        let Some(selection_proof) = duty_and_proof.selection_proof else {
                            continue;
                        };

                        let (existing_dependent_root, existing_duty) = entry.get_mut();

                        if *existing_dependent_root == dependent_root {
                            // Replace existing proof.
                            existing_duty.selection_proof = Some(selection_proof);
                        } else {
                            // Our selection proofs are no longer relevant due to a reorg, abandon
                            // this entire background process.
                            debug!(
                                log,
                                "Stopping selection proof background task";
                                "reason" => "re-org"
                            );
                            return;
                        }
                    }
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert((dependent_root, duty_and_proof));
                    }
                }
            }
            drop(attesters);

            let time_taken_ms =
                Duration::from_secs_f64(timer.map_or(0.0, |t| t.stop_and_record())).as_millis();
            debug!(
                log,
                "Computed attestation selection proofs";
                "batch_size" => batch_size,
                "lookahead_slot" => lookahead_slot,
                "time_taken_ms" => time_taken_ms
            );
        } else {
            // Just sleep for one slot if we are unable to read the system clock, this gives
            // us an opportunity for the clock to eventually come good.
            sleep(duties_service.slot_clock.slot_duration()).await;
        }
    }
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
            .first_success(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::DUTIES_SERVICE_TIMES,
                        &[metrics::PROPOSER_DUTIES_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_duties_proposer(current_epoch)
                        .await
                },
            )
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
