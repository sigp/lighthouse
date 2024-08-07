//! The `DutiesService` contains the attester/proposer duties for all local validators.
//!
//! It learns of the local validator via the `crate::ValidatorStore` struct. It keeps the duties
//! up-to-date by polling the beacon node on regular intervals.
//!
//! The `DutiesService` is also responsible for sending events to the `BlockService` which trigger
//! block production.

pub mod sync;

use crate::beacon_node_fallback::{ApiTopic, BeaconNodeFallback, OfflineOnFailure, RequireSynced};
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
use safe_arith::{ArithError, SafeArith};
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::cmp::min;
use std::collections::{hash_map, BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sync::poll_sync_committee_duties;
use sync::SyncDutiesMap;
use tokio::{sync::mpsc::Sender, time::sleep};
use types::{ChainSpec, Epoch, EthSpec, Hash256, PublicKeyBytes, SelectionProof, Slot};

/// Only retain `HISTORICAL_DUTIES_EPOCHS` duties prior to the current epoch.
const HISTORICAL_DUTIES_EPOCHS: u64 = 2;

/// Compute attestation selection proofs this many slots before they are required.
///
/// At start-up selection proofs will be computed with less lookahead out of necessity.
const SELECTION_PROOF_SLOT_LOOKAHEAD: u64 = 8;

/// The attestation selection proof lookahead for those running with the --distributed flag.
const SELECTION_PROOF_SLOT_LOOKAHEAD_DVT: u64 = 1;

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

/// Offsets from the attestation duty slot at which a subscription should be sent.
const ATTESTATION_SUBSCRIPTION_OFFSETS: [u64; 8] = [3, 4, 5, 6, 7, 8, 16, 32];

/// Check that `ATTESTATION_SUBSCRIPTION_OFFSETS` is sorted ascendingly.
const _: () = assert!({
    let mut i = 0;
    loop {
        let prev = if i > 0 {
            ATTESTATION_SUBSCRIPTION_OFFSETS[i - 1]
        } else {
            0
        };
        let curr = ATTESTATION_SUBSCRIPTION_OFFSETS[i];
        if curr < prev {
            break false;
        }
        i += 1;
        if i == ATTESTATION_SUBSCRIPTION_OFFSETS.len() {
            break true;
        }
    }
});
/// Since the BN does not like it when we subscribe to slots that are close to the current time, we
/// will only subscribe to slots which are further than 2 slots away.
///
/// This number is based upon `MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD` value in the
/// `beacon_node::network::attestation_service` crate. It is not imported directly to avoid
/// bringing in the entire crate.
const MIN_ATTESTATION_SUBSCRIPTION_LOOKAHEAD: u64 = 2;
const _: () = assert!(ATTESTATION_SUBSCRIPTION_OFFSETS[0] > MIN_ATTESTATION_SUBSCRIPTION_LOOKAHEAD);

// The info in the enum variants is displayed in logging, clippy thinks it's dead code.
#[derive(Debug)]
pub enum Error {
    UnableToReadSlotClock,
    FailedToDownloadAttesters(#[allow(dead_code)] String),
    FailedToProduceSelectionProof(#[allow(dead_code)] ValidatorStoreError),
    InvalidModulo(#[allow(dead_code)] ArithError),
    Arith(#[allow(dead_code)] ArithError),
    SyncDutiesNotFound(#[allow(dead_code)] u64),
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
    /// Track which slots we should send subscriptions at for this duty.
    ///
    /// This value is updated after each subscription is successfully sent.
    pub subscription_slots: Arc<SubscriptionSlots>,
}

/// Tracker containing the slots at which an attestation subscription should be sent.
pub struct SubscriptionSlots {
    /// Pairs of `(slot, already_sent)` in slot-descending order.
    slots: Vec<(Slot, AtomicBool)>,
    /// The slot of the duty itself.
    duty_slot: Slot,
}

/// Create a selection proof for `duty`.
///
/// Return `Ok(None)` if the attesting validator is not an aggregator.
async fn make_selection_proof<T: SlotClock + 'static, E: EthSpec>(
    duty: &AttesterData,
    validator_store: &ValidatorStore<T, E>,
    spec: &ChainSpec,
) -> Result<Option<SelectionProof>, Error> {
    let selection_proof = validator_store
        .produce_selection_proof(duty.pubkey, duty.slot)
        .await
        .map_err(Error::FailedToProduceSelectionProof)?;

    selection_proof
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
        })
}

impl DutyAndProof {
    /// Create a new `DutyAndProof` with the selection proof waiting to be filled in.
    pub fn new_without_selection_proof(duty: AttesterData, current_slot: Slot) -> Self {
        let subscription_slots = SubscriptionSlots::new(duty.slot, current_slot);
        Self {
            duty,
            selection_proof: None,
            subscription_slots,
        }
    }
}

impl SubscriptionSlots {
    fn new(duty_slot: Slot, current_slot: Slot) -> Arc<Self> {
        let slots = ATTESTATION_SUBSCRIPTION_OFFSETS
            .into_iter()
            .filter_map(|offset| duty_slot.safe_sub(offset).ok())
            // Keep only scheduled slots that haven't happened yet. This avoids sending expired
            // subscriptions.
            .filter(|scheduled_slot| *scheduled_slot > current_slot)
            .map(|scheduled_slot| (scheduled_slot, AtomicBool::new(false)))
            .collect();
        Arc::new(Self { slots, duty_slot })
    }

    /// Return `true` if we should send a subscription at `slot`.
    fn should_send_subscription_at(&self, slot: Slot) -> bool {
        // Iterate slots from smallest to largest looking for one that hasn't been completed yet.
        slot + MIN_ATTESTATION_SUBSCRIPTION_LOOKAHEAD <= self.duty_slot
            && self
                .slots
                .iter()
                .rev()
                .any(|(scheduled_slot, already_sent)| {
                    slot >= *scheduled_slot && !already_sent.load(Ordering::Relaxed)
                })
    }

    /// Update our record of subscribed slots to account for successful subscription at `slot`.
    fn record_successful_subscription_at(&self, slot: Slot) {
        for (scheduled_slot, already_sent) in self.slots.iter().rev() {
            if slot >= *scheduled_slot {
                already_sent.store(true, Ordering::Relaxed);
            } else {
                break;
            }
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
    pub sync_duties: SyncDutiesMap<E>,
    /// Provides the canonical list of locally-managed validators.
    pub validator_store: Arc<ValidatorStore<T, E>>,
    /// Maps unknown validator pubkeys to the next slot time when a poll should be conducted again.
    pub unknown_validator_next_poll_slots: RwLock<HashMap<PublicKeyBytes, Slot>>,
    /// Tracks the current slot.
    pub slot_clock: T,
    /// Provides HTTP access to remote beacon nodes.
    pub beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    /// The runtime for spawning tasks.
    pub context: RuntimeContext<E>,
    /// The current chain spec.
    pub spec: ChainSpec,
    //// Whether we permit large validator counts in the metrics.
    pub enable_high_validator_count_metrics: bool,
    /// If this validator is running in distributed mode.
    pub distributed: bool,
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
            let current_slot_opt = duties_service.slot_clock.now();

            if let Some(current_slot) = current_slot_opt {
                let is_first_slot_of_epoch = current_slot % E::slots_per_epoch() == 0;

                // Query an unknown validator later if it was queried within the last epoch, or if
                // the current slot is the first slot of an epoch.
                let poll_later = duties_service
                    .unknown_validator_next_poll_slots
                    .read()
                    .get(&pubkey)
                    .map(|&poll_slot| poll_slot > current_slot || is_first_slot_of_epoch)
                    .unwrap_or(false);
                if poll_later {
                    continue;
                }
            }

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

                    duties_service
                        .unknown_validator_next_poll_slots
                        .write()
                        .remove(&pubkey);
                }
                // This is not necessarily an error, it just means the validator is not yet known to
                // the beacon chain.
                Ok(None) => {
                    if let Some(current_slot) = current_slot_opt {
                        let next_poll_slot = current_slot.saturating_add(E::slots_per_epoch());
                        duties_service
                            .unknown_validator_next_poll_slots
                            .write()
                            .insert(pubkey, next_poll_slot);
                    }

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

    // This vector is intentionally oversized by 10% so that it won't reallocate.
    // Each validator has 2 attestation duties occuring in the current and next epoch, for which
    // they must send `ATTESTATION_SUBSCRIPTION_OFFSETS.len()` subscriptions. These subscription
    // slots are approximately evenly distributed over the two epochs, usually with a slight lag
    // that balances out (some subscriptions for the current epoch were sent in the previous, and
    // some subscriptions for the next next epoch will be sent in the next epoch but aren't included
    // in our calculation). We cancel the factor of 2 from the formula for simplicity.
    let overallocation_numerator = 110;
    let overallocation_denominator = 100;
    let num_expected_subscriptions = overallocation_numerator
        * std::cmp::max(
            1,
            local_pubkeys.len() * ATTESTATION_SUBSCRIPTION_OFFSETS.len()
                / E::slots_per_epoch() as usize,
        )
        / overallocation_denominator;
    let mut subscriptions = Vec::with_capacity(num_expected_subscriptions);
    let mut subscription_slots_to_confirm = Vec::with_capacity(num_expected_subscriptions);

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
            .filter(|(_, duty_and_proof)| {
                duty_and_proof
                    .subscription_slots
                    .should_send_subscription_at(current_slot)
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
                });
                subscription_slots_to_confirm.push(duty_and_proof.subscription_slots.clone());
            });
    }

    // If there are any subscriptions, push them out to beacon nodes
    if !subscriptions.is_empty() {
        let subscriptions_ref = &subscriptions;
        let subscription_result = duties_service
            .beacon_nodes
            .request(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                ApiTopic::Subscriptions,
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
            .await;
        if subscription_result.as_ref().is_ok() {
            debug!(
                log,
                "Broadcast attestation subscriptions";
                "count" => subscriptions.len(),
            );
            for subscription_slots in subscription_slots_to_confirm {
                subscription_slots.record_successful_subscription_at(current_slot);
            }
        } else if let Err(e) = subscription_result {
            if e.num_errors() < duties_service.beacon_nodes.num_total() {
                warn!(
                    log,
                    "Some subscriptions failed";
                    "error" => %e,
                );
                // If subscriptions were sent to at least one node, regard that as a success.
                // There is some redundancy built into the subscription schedule to handle failures.
                for subscription_slots in subscription_slots_to_confirm {
                    subscription_slots.record_successful_subscription_at(current_slot);
                }
            } else {
                error!(
                    log,
                    "All subscriptions failed";
                    "error" => %e
                );
            }
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
    let initial_indices_to_request = if !uninitialized_validators.is_empty() {
        uninitialized_validators.as_slice()
    } else {
        &local_indices[0..min(INITIAL_DUTIES_QUERY_SIZE, local_indices.len())]
    };

    let response =
        post_validator_duties_attester(duties_service, epoch, initial_indices_to_request).await?;
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

    // Make a request for all indices that require updating which we have not already made a request
    // for.
    let indices_to_request = validators_to_update
        .iter()
        .filter_map(|pubkey| duties_service.validator_store.validator_index(pubkey))
        .filter(|validator_index| !initial_indices_to_request.contains(validator_index))
        .collect::<Vec<_>>();

    // Filter the initial duties by their relevance so that we don't hit the warning below about
    // overwriting duties. There was previously a bug here.
    let new_initial_duties = response
        .data
        .into_iter()
        .filter(|duty| validators_to_update.contains(&&duty.pubkey));

    let mut new_duties = if !indices_to_request.is_empty() {
        post_validator_duties_attester(duties_service, epoch, indices_to_request.as_slice())
            .await?
            .data
    } else {
        vec![]
    };
    new_duties.extend(new_initial_duties);

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
    let current_slot = duties_service
        .slot_clock
        .now_or_genesis()
        .unwrap_or_default();
    for duty in &new_duties {
        let attester_map = attesters.entry(duty.pubkey).or_default();

        // Create initial entries in the map without selection proofs. We'll compute them in the
        // background later to avoid creating a thundering herd of signing threads whenever new
        // duties are computed.
        let duty_and_proof = DutyAndProof::new_without_selection_proof(duty.clone(), current_slot);

        match attester_map.entry(epoch) {
            hash_map::Entry::Occupied(mut occupied) => {
                let mut_value = occupied.get_mut();
                let (prior_dependent_root, prior_duty_and_proof) = &mut_value;

                // Guard against overwriting an existing value for the same duty. If we did
                // overwrite we could lose a selection proof or information from
                // `subscription_slots`. Hitting this branch should be prevented by our logic for
                // fetching duties only for unknown indices.
                if dependent_root == *prior_dependent_root
                    && prior_duty_and_proof.duty == duty_and_proof.duty
                {
                    warn!(
                        log,
                        "Redundant attester duty update";
                        "dependent_root" => %dependent_root,
                        "validator_index" => duty.validator_index,
                    );
                    continue;
                }

                // Using `already_warned` avoids excessive logs.
                if dependent_root != *prior_dependent_root && already_warned.take().is_some() {
                    warn!(
                        log,
                        "Attester duties re-org";
                        "prior_dependent_root" => %prior_dependent_root,
                        "dependent_root" => %dependent_root,
                        "note" => "this may happen from time to time"
                    )
                }
                *mut_value = (dependent_root, duty_and_proof);
            }
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert((dependent_root, duty_and_proof));
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

            let selection_lookahead = if duties_service.distributed {
                SELECTION_PROOF_SLOT_LOOKAHEAD_DVT
            } else {
                SELECTION_PROOF_SLOT_LOOKAHEAD
            };

            let lookahead_slot = current_slot + selection_lookahead;

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
                    let opt_selection_proof = make_selection_proof(
                        &duty,
                        &duties_service.validator_store,
                        &duties_service.spec,
                    )
                    .await?;
                    Ok((duty, opt_selection_proof))
                })
                .collect::<Vec<_>>()
                .await;

            // Add to attesters store.
            let mut attesters = duties_service.attesters.write();
            for result in duty_and_proof_results {
                let (duty, selection_proof) = match result {
                    Ok(duty_and_proof) => duty_and_proof,
                    Err(Error::FailedToProduceSelectionProof(
                        ValidatorStoreError::UnknownPubkey(pubkey),
                    )) => {
                        // A pubkey can be missing when a validator was recently
                        // removed via the API.
                        warn!(
                            log,
                            "Missing pubkey for duty and proof";
                            "info" => "a validator may have recently been removed from this VC",
                            "pubkey" => ?pubkey,
                        );
                        // Do not abort the entire batch for a single failure.
                        continue;
                    }
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

                let attester_map = attesters.entry(duty.pubkey).or_default();
                let epoch = duty.slot.epoch(E::slots_per_epoch());
                match attester_map.entry(epoch) {
                    hash_map::Entry::Occupied(mut entry) => {
                        // No need to update duties for which no proof was computed.
                        let Some(selection_proof) = selection_proof else {
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
                        // This probably shouldn't happen, but we have enough info to fill in the
                        // entry so we may as well.
                        let subscription_slots = SubscriptionSlots::new(duty.slot, current_slot);
                        let duty_and_proof = DutyAndProof {
                            duty,
                            selection_proof,
                            subscription_slots,
                        };
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
/// producers that were not included in the first notification. This should be safe enough.
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn subscription_slots_exact() {
        // Set current slot in the past so no duties are considered expired.
        let current_slot = Slot::new(0);
        for duty_slot in [
            Slot::new(33),
            Slot::new(47),
            Slot::new(99),
            Slot::new(1002003),
        ] {
            let subscription_slots = SubscriptionSlots::new(duty_slot, current_slot);

            // Run twice to check idempotence (subscription slots shouldn't be marked as done until
            // we mark them manually).
            for _ in 0..2 {
                for offset in ATTESTATION_SUBSCRIPTION_OFFSETS {
                    assert!(subscription_slots.should_send_subscription_at(duty_slot - offset));
                }
            }

            // Mark each slot as complete and check that all prior slots are still marked
            // incomplete.
            for (i, offset) in ATTESTATION_SUBSCRIPTION_OFFSETS
                .into_iter()
                .rev()
                .enumerate()
            {
                subscription_slots.record_successful_subscription_at(duty_slot - offset);
                for lower_offset in ATTESTATION_SUBSCRIPTION_OFFSETS
                    .into_iter()
                    .rev()
                    .skip(i + 1)
                {
                    assert!(lower_offset < offset);
                    assert!(
                        subscription_slots.should_send_subscription_at(duty_slot - lower_offset)
                    );
                }
            }
        }
    }
    #[test]
    fn subscription_slots_mark_multiple() {
        for (i, offset) in ATTESTATION_SUBSCRIPTION_OFFSETS.into_iter().enumerate() {
            let current_slot = Slot::new(0);
            let duty_slot = Slot::new(64);
            let subscription_slots = SubscriptionSlots::new(duty_slot, current_slot);

            subscription_slots.record_successful_subscription_at(duty_slot - offset);

            // All past offsets (earlier slots) should be marked as complete.
            for (j, other_offset) in ATTESTATION_SUBSCRIPTION_OFFSETS.into_iter().enumerate() {
                let past = j >= i;
                assert_eq!(other_offset >= offset, past);
                assert_eq!(
                    subscription_slots.should_send_subscription_at(duty_slot - other_offset),
                    !past
                );
            }
        }
    }

    /// Test the boundary condition where all subscription slots are *just* expired.
    #[test]
    fn subscription_slots_expired() {
        let current_slot = Slot::new(100);
        let duty_slot = current_slot + ATTESTATION_SUBSCRIPTION_OFFSETS[0];
        let subscription_slots = SubscriptionSlots::new(duty_slot, current_slot);
        for offset in ATTESTATION_SUBSCRIPTION_OFFSETS.into_iter() {
            let slot = duty_slot - offset;
            assert!(!subscription_slots.should_send_subscription_at(slot));
        }
        assert!(subscription_slots.slots.is_empty());

        // If the duty slot is 1 later, we get a non-empty set of duties.
        let subscription_slots = SubscriptionSlots::new(duty_slot + 1, current_slot);
        assert_eq!(subscription_slots.slots.len(), 1);
        assert!(subscription_slots.should_send_subscription_at(current_slot + 1),);
    }
}
