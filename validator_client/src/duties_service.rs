use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{
    block_service::BlockServiceNotification, http_metrics::metrics, validator_duty::ValidatorDuty,
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use futures::channel::mpsc::Sender;
use futures::SinkExt;
use parking_lot::RwLock;
use slog::{debug, error, trace, warn};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use types::{ChainSpec, CommitteeIndex, Epoch, EthSpec, PublicKey, SelectionProof, Slot};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

/// Remove any duties where the `duties_epoch < current_epoch - PRUNE_DEPTH`.
const PRUNE_DEPTH: u64 = 4;

type BaseHashMap = HashMap<PublicKey, HashMap<Epoch, DutyAndProof>>;

#[derive(Debug, Clone)]
pub struct DutyAndProof {
    /// The validator duty.
    pub duty: ValidatorDuty,
    /// Stores the selection proof if the duty elects the validator to be an aggregator.
    pub selection_proof: Option<SelectionProof>,
}

impl DutyAndProof {
    /// Computes the selection proof for `self.validator_pubkey` and `self.duty.attestation_slot`,
    /// storing it in `self.selection_proof` _if_ the validator is an aggregator. If the validator
    /// is not an aggregator, `self.selection_proof` is set to `None`.
    ///
    /// ## Errors
    ///
    /// - `self.validator_pubkey` is not known in `validator_store`.
    /// - There's an arith error during computation.
    pub fn compute_selection_proof<T: SlotClock + 'static, E: EthSpec>(
        &mut self,
        validator_store: &ValidatorStore<T, E>,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let (committee_length, slot) = if let (Some(count), Some(slot)) =
            (self.duty.committee_length, self.duty.attestation_slot)
        {
            (count as usize, slot)
        } else {
            // If there are no attester duties we assume the validator is inactive.
            self.selection_proof = None;
            return Ok(());
        };

        let selection_proof = validator_store
            .produce_selection_proof(&self.duty.validator_pubkey, slot)
            .ok_or("Failed to produce selection proof")?;

        self.selection_proof = selection_proof
            .is_aggregator(committee_length, spec)
            .map_err(|e| format!("Invalid modulo: {:?}", e))
            .map(|is_aggregator| {
                if is_aggregator {
                    Some(selection_proof)
                } else {
                    None
                }
            })?;

        Ok(())
    }

    /// Returns `true` if the two `Self` instances would result in the same beacon subscription.
    pub fn subscription_eq(&self, other: &Self) -> bool {
        self.selection_proof_eq(other)
            && self.duty.validator_index == other.duty.validator_index
            && self.duty.attestation_committee_index == other.duty.attestation_committee_index
            && self.duty.attestation_slot == other.duty.attestation_slot
    }

    /// Returns `true` if the selection proof between `self` and `other` _should_ be equal.
    ///
    /// It's important to note that this doesn't actually check `self.selection_proof`, instead it
    /// checks to see if the inputs to computing the selection proof are equal.
    fn selection_proof_eq(&self, other: &Self) -> bool {
        self.duty.committee_count_at_slot == other.duty.committee_count_at_slot
            && self.duty.attestation_slot == other.duty.attestation_slot
    }

    /// Returns the information required for an attesting validator, if they are scheduled to
    /// attest.
    pub fn attestation_duties(&self) -> Option<(Slot, CommitteeIndex, usize, u64, u64, u64)> {
        Some((
            self.duty.attestation_slot?,
            self.duty.attestation_committee_index?,
            self.duty.attestation_committee_position?,
            self.duty.validator_index?,
            self.duty.committee_count_at_slot?,
            self.duty.committee_length?,
        ))
    }

    pub fn validator_pubkey(&self) -> &PublicKey {
        &self.duty.validator_pubkey
    }

    pub fn validator_index(&self) -> Option<u64> {
        self.duty.validator_index
    }
}

impl Into<DutyAndProof> for ValidatorDuty {
    fn into(self) -> DutyAndProof {
        DutyAndProof {
            duty: self,
            selection_proof: None,
        }
    }
}

/// The outcome of inserting some `ValidatorDuty` into the `DutiesStore`.
#[derive(PartialEq, Debug, Clone)]
enum InsertOutcome {
    /// These are the first duties received for this validator.
    NewValidator,
    /// The duties for this given epoch were previously unknown and have been stored.
    NewEpoch,
    /// The duties were identical to some already in the store.
    Identical,
    /// The duties informed us of new proposal slots but were otherwise identical.
    NewProposalSlots,
    /// There were duties for this validator and epoch in the store that were different to the ones
    /// provided. The existing duties were replaced.
    Replaced { should_resubscribe: bool },
    /// The given duties were invalid.
    Invalid,
}

impl InsertOutcome {
    /// Returns `true` if the outcome indicates that the validator _might_ require a subscription.
    pub fn is_subscription_candidate(&self) -> bool {
        match self {
            InsertOutcome::Replaced { should_resubscribe } => *should_resubscribe,
            InsertOutcome::NewValidator | InsertOutcome::NewEpoch => true,
            InsertOutcome::Identical | InsertOutcome::Invalid | InsertOutcome::NewProposalSlots => {
                false
            }
        }
    }
}

#[derive(Default)]
pub struct DutiesStore {
    store: RwLock<BaseHashMap>,
}

impl DutiesStore {
    /// Returns the total number of validators that should propose in the given epoch.
    fn proposer_count(&self, epoch: Epoch) -> usize {
        self.store
            .read()
            .iter()
            .filter(|(_validator_pubkey, validator_map)| {
                validator_map
                    .get(&epoch)
                    .map(|duties| {
                        duties
                            .duty
                            .block_proposal_slots
                            .as_ref()
                            .map_or(false, |proposal_slots| !proposal_slots.is_empty())
                    })
                    .unwrap_or(false)
            })
            .count()
    }

    /// Returns the total number of validators that should attest in the given epoch.
    fn attester_count(&self, epoch: Epoch) -> usize {
        self.store
            .read()
            .iter()
            .filter(|(_validator_pubkey, validator_map)| {
                validator_map
                    .get(&epoch)
                    .map(|duties| duties.duty.attestation_slot.is_some())
                    .unwrap_or_else(|| false)
            })
            .count()
    }

    fn block_proposers(&self, slot: Slot, slots_per_epoch: u64) -> Vec<PublicKey> {
        self.store
            .read()
            .iter()
            // As long as a `HashMap` iterator does not return duplicate keys, neither will this
            // function.
            .filter_map(|(_validator_pubkey, validator_map)| {
                let epoch = slot.epoch(slots_per_epoch);

                validator_map.get(&epoch).and_then(|duties| {
                    if duties.duty.block_proposal_slots.as_ref()?.contains(&slot) {
                        Some(duties.duty.validator_pubkey.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    fn attesters(&self, slot: Slot, slots_per_epoch: u64) -> Vec<DutyAndProof> {
        self.store
            .read()
            .iter()
            // As long as a `HashMap` iterator does not return duplicate keys, neither will this
            // function.
            .filter_map(|(_validator_pubkey, validator_map)| {
                let epoch = slot.epoch(slots_per_epoch);

                validator_map.get(&epoch).and_then(|duties| {
                    if duties.duty.attestation_slot == Some(slot) {
                        Some(duties)
                    } else {
                        None
                    }
                })
            })
            .cloned()
            .collect()
    }

    fn get_index(&self, pubkey: &PublicKey, epoch: Epoch) -> Option<u64> {
        self.store
            .read()
            .get(pubkey)?
            .get(&epoch)?
            .validator_index()
    }

    fn is_aggregator(&self, validator_pubkey: &PublicKey, epoch: Epoch) -> Option<bool> {
        Some(
            self.store
                .read()
                .get(validator_pubkey)?
                .get(&epoch)?
                .selection_proof
                .is_some(),
        )
    }

    fn insert<T: SlotClock + 'static, E: EthSpec>(
        &self,
        epoch: Epoch,
        mut duties: DutyAndProof,
        slots_per_epoch: u64,
        validator_store: &ValidatorStore<T, E>,
        spec: &ChainSpec,
    ) -> Result<InsertOutcome, String> {
        let mut store = self.store.write();

        if !duties_match_epoch(&duties.duty, epoch, slots_per_epoch) {
            return Ok(InsertOutcome::Invalid);
        }

        // TODO: refactor with Entry.

        if let Some(validator_map) = store.get_mut(&duties.duty.validator_pubkey) {
            if let Some(known_duties) = validator_map.get_mut(&epoch) {
                if known_duties.duty.eq_ignoring_proposal_slots(&duties.duty) {
                    if known_duties.duty.block_proposal_slots == duties.duty.block_proposal_slots {
                        Ok(InsertOutcome::Identical)
                    } else if duties.duty.block_proposal_slots.is_some() {
                        known_duties.duty.block_proposal_slots = duties.duty.block_proposal_slots;
                        Ok(InsertOutcome::NewProposalSlots)
                    } else {
                        Ok(InsertOutcome::Invalid)
                    }
                } else {
                    // Compute the selection proof.
                    duties.compute_selection_proof(validator_store, spec)?;

                    // Determine if a re-subscription is required.
                    let should_resubscribe = !duties.subscription_eq(known_duties);

                    // Replace the existing duties.
                    *known_duties = duties;

                    Ok(InsertOutcome::Replaced { should_resubscribe })
                }
            } else {
                // Compute the selection proof.
                duties.compute_selection_proof(validator_store, spec)?;

                validator_map.insert(epoch, duties);

                Ok(InsertOutcome::NewEpoch)
            }
        } else {
            // Compute the selection proof.
            duties.compute_selection_proof(validator_store, spec)?;

            let validator_pubkey = duties.duty.validator_pubkey.clone();

            let mut validator_map = HashMap::new();
            validator_map.insert(epoch, duties);

            store.insert(validator_pubkey, validator_map);

            Ok(InsertOutcome::NewValidator)
        }
    }

    fn prune(&self, prior_to: Epoch) {
        self.store
            .write()
            .retain(|_validator_pubkey, validator_map| {
                validator_map.retain(|epoch, _duties| *epoch >= prior_to);
                !validator_map.is_empty()
            });
    }
}

pub struct DutiesServiceBuilder<T: SlotClock + 'static, E: EthSpec> {
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    allow_unsynced_beacon_node: bool,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            allow_unsynced_beacon_node: false,
            context: None,
        }
    }

    pub fn validator_store(mut self, store: ValidatorStore<T, E>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn allow_unsynced_beacon_node(mut self, allow_unsynced_beacon_node: bool) -> Self {
        self.allow_unsynced_beacon_node = allow_unsynced_beacon_node;
        self
    }

    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.context = Some(context);
        self
    }

    pub fn build(self) -> Result<DutiesService<T, E>, String> {
        Ok(DutiesService {
            inner: Arc::new(Inner {
                store: Arc::new(DutiesStore::default()),
                validator_store: self
                    .validator_store
                    .ok_or("Cannot build DutiesService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build DutiesService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build DutiesService without beacon_node")?,
                allow_unsynced_beacon_node: self.allow_unsynced_beacon_node,
                context: self
                    .context
                    .ok_or("Cannot build DutiesService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    store: Arc<DutiesStore>,
    validator_store: ValidatorStore<T, E>,
    pub(crate) slot_clock: T,
    pub(crate) beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    allow_unsynced_beacon_node: bool,
    context: RuntimeContext<E>,
}

/// Maintains a store of the duties for all voting validators in the `validator_store`.
///
/// Polls the beacon node at the start of each slot, collecting duties for the current and next
/// epoch. The duties service notifies the block production service to run each time it completes,
/// so it *must* be run every slot.
pub struct DutiesService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for DutiesService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for DutiesService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesService<T, E> {
    /// Returns the total number of validators known to the duties service.
    pub fn total_validator_count(&self) -> usize {
        self.validator_store.num_voting_validators()
    }

    /// Returns the total number of validators that should propose in the given epoch.
    pub fn proposer_count(&self, epoch: Epoch) -> usize {
        self.store.proposer_count(epoch)
    }

    /// Returns the total number of validators that should attest in the given epoch.
    pub fn attester_count(&self, epoch: Epoch) -> usize {
        self.store.attester_count(epoch)
    }

    /// Returns the pubkeys of the validators which are assigned to propose in the given slot.
    ///
    /// It is possible that multiple validators have an identical proposal slot, however that is
    /// likely the result of heavy forking (lol) or inconsistent beacon node connections.
    pub fn block_proposers(&self, slot: Slot) -> Vec<PublicKey> {
        self.store.block_proposers(slot, E::slots_per_epoch())
    }

    /// Returns all `ValidatorDuty` for the given `slot`.
    pub fn attesters(&self, slot: Slot) -> Vec<DutyAndProof> {
        self.store.attesters(slot, E::slots_per_epoch())
    }

    /// Start the service that periodically polls the beacon node for validator duties.
    pub fn start_update_service(
        self,
        mut block_service_tx: Sender<BlockServiceNotification>,
        spec: Arc<ChainSpec>,
    ) -> Result<(), String> {
        // Run an immediate update before starting the updater service.
        let duties_service = self.clone();
        let mut block_service_tx_clone = block_service_tx.clone();
        let inner_spec = spec.clone();
        self.inner.context.executor.spawn(
            async move {
                duties_service
                    .do_update(&mut block_service_tx_clone, &inner_spec)
                    .await
            },
            "duties update",
        );

        let executor = self.inner.context.executor.clone();

        let interval_fut = async move {
            while let Some(duration_to_next_slot) = self.clone().slot_clock.duration_to_next_slot()
            {
                // TODO(pawan): double check timing here
                sleep(duration_to_next_slot + TIME_DELAY_FROM_SLOT).await;
                self.clone().update(&mut block_service_tx, &spec);
            }
        };

        executor.spawn(interval_fut, "duties_service");

        Ok(())
    }

    /// Spawns a new duties update task.
    fn update(self, block_service_tx: &mut Sender<BlockServiceNotification>, spec: &ChainSpec) {
        let executor = self.inner.context.executor.clone();
        let mut block_service_tx_clone = block_service_tx.clone();
        let inner_spec = spec.clone();
        executor.spawn(
            async move {
                self.do_update(&mut block_service_tx_clone, &inner_spec)
                    .await
            },
            "duties_service_task",
        );
    }

    /// Attempt to download the duties of all managed validators for this epoch and the next.
    async fn do_update(
        self,
        block_service_tx: &mut Sender<BlockServiceNotification>,
        spec: &ChainSpec,
    ) {
        let log = self.context.log();
        let _timer =
            metrics::start_timer_vec(&metrics::DUTIES_SERVICE_TIMES, &[metrics::FULL_UPDATE]);

        let slot = if let Some(slot) = self.slot_clock.now() {
            slot
        } else {
            error!(log, "Duties manager failed to read slot clock");
            return;
        };

        let current_epoch = slot.epoch(E::slots_per_epoch());

        if slot % E::slots_per_epoch() == 0 {
            let prune_below = current_epoch - PRUNE_DEPTH;

            trace!(
                log,
                "Pruning duties cache";
                "pruning_below" => prune_below.as_u64(),
                "current_epoch" => current_epoch.as_u64(),
            );

            self.store.prune(prune_below);
        }

        // Update duties for the current epoch, but keep running if there's an error:
        // block production or the next epoch update could still succeed.
        if let Err(e) = self
            .clone()
            .update_epoch(current_epoch, current_epoch, spec)
            .await
        {
            error!(
                log,
                "Failed to get current epoch duties";
                "http_error" => format!("{:?}", e)
            );
        }

        // Notify the block service to produce a block.
        if let Err(e) = block_service_tx
            .send(BlockServiceNotification {
                slot,
                block_proposers: self.block_proposers(slot),
            })
            .await
        {
            error!(
                log,
                "Failed to notify block service";
                "error" => format!("{:?}", e)
            );
        };

        // Update duties for the next epoch.
        if let Err(e) = self
            .clone()
            .update_epoch(current_epoch, current_epoch + 1, spec)
            .await
        {
            error!(
                log,
                "Failed to get next epoch duties";
                "http_error" => format!("{:?}", e)
            );
        }
    }

    /// Attempt to download the duties of all managed validators for the given `request_epoch`. The
    /// `current_epoch` should be a local reading of the slot clock.
    async fn update_epoch(
        self,
        current_epoch: Epoch,
        request_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let log = self.context.log();

        let maybe_require_synced = if self.allow_unsynced_beacon_node {
            RequireSynced::No
        } else {
            RequireSynced::Yes
        };

        let mut new_validator = 0;
        let mut new_epoch = 0;
        let mut new_proposal_slots = 0;
        let mut identical = 0;
        let mut replaced = 0;
        let mut invalid = 0;

        // Determine which pubkeys we already know the index of by checking the duties store for
        // the current epoch.
        let pubkeys: Vec<(PublicKey, Option<u64>)> = self
            .validator_store
            .voting_pubkeys()
            .into_iter()
            .map(|pubkey| {
                let index = self.store.get_index(&pubkey, current_epoch);
                (pubkey, index)
            })
            .collect();

        let mut validator_subscriptions = vec![];
        let pubkeys_ref = &pubkeys;
        let remote_duties: Vec<ValidatorDuty> = match self
            .beacon_nodes
            .first_success(maybe_require_synced, |beacon_node| async move {
                ValidatorDuty::download(
                    &beacon_node,
                    current_epoch,
                    request_epoch,
                    pubkeys_ref.clone(),
                    &log,
                )
                .await
            })
            .await
        {
            Ok(duties) => duties,
            Err(e) => {
                error!(
                    log,
                    "Failed to download validator duties";
                    "error" => %e
                );
                vec![]
            }
        };

        remote_duties.iter().for_each(|remote_duty| {
            // Convert the remote duties into our local representation.
            let duties: DutyAndProof = remote_duty.clone().into();

            let validator_pubkey = duties.duty.validator_pubkey.clone();

            // Attempt to update our local store.
            match self.store.insert(
                request_epoch,
                duties,
                E::slots_per_epoch(),
                &self.validator_store,
                spec,
            ) {
                Ok(outcome) => {
                    match &outcome {
                        InsertOutcome::NewValidator => {
                            debug!(
                                log,
                                "First duty assignment for validator";
                                "proposal_slots" => format!("{:?}", &remote_duty.block_proposal_slots),
                                "attestation_slot" => format!("{:?}", &remote_duty.attestation_slot),
                                "validator" => format!("{:?}", &remote_duty.validator_pubkey)
                            );
                            new_validator += 1;
                        }
                        InsertOutcome::NewProposalSlots => new_proposal_slots += 1,
                        InsertOutcome::NewEpoch => new_epoch += 1,
                        InsertOutcome::Identical => identical += 1,
                        InsertOutcome::Replaced { .. } => replaced += 1,
                        InsertOutcome::Invalid => invalid += 1,
                    }

                    if let Some(is_aggregator) =
                    self.store.is_aggregator(&validator_pubkey, request_epoch)
                    {
                        if outcome.is_subscription_candidate() {
                            if let Some(subscription) = remote_duty.subscription(is_aggregator) {
                                validator_subscriptions.push(subscription)
                            }
                        }
                    }
                }
                Err(e) => error!(
                    log,
                    "Unable to store duties";
                    "error" => e
                ),
            }
        });

        if invalid > 0 {
            error!(
                log,
                "Received invalid duties from beacon node";
                "bad_duty_count" => invalid,
                "info" => "Duties are from wrong epoch."
            )
        }

        trace!(
            log,
            "Performed duties update";
            "identical" => identical,
            "new_epoch" => new_epoch,
            "new_proposal_slots" => new_proposal_slots,
            "new_validator" => new_validator,
            "replaced" => replaced,
            "epoch" => format!("{}", request_epoch)
        );

        if replaced > 0 {
            warn!(
                log,
                "Duties changed during routine update";
                "info" => "Chain re-org likely occurred",
                "replaced" => replaced,
            )
        }

        let log = self.context.log().clone();
        let count = validator_subscriptions.len();

        if count == 0 {
            debug!(log, "No new subscriptions required");
        } else {
            let validator_subscriptions_ref = &validator_subscriptions;
            self.beacon_nodes
                .first_success(RequireSynced::No, |beacon_node| async move {
                    beacon_node
                        .post_validator_beacon_committee_subscriptions(validator_subscriptions_ref)
                        .await
                })
                .await
                .map_err(|e| format!("Failed to subscribe validators: {}", e))?;

            debug!(
                log,
                "Successfully subscribed validators";
                "count" => count
            );
        }

        Ok(())
    }
}

/// Returns `true` if the slots in the `duties` are from the given `epoch`
fn duties_match_epoch(duties: &ValidatorDuty, epoch: Epoch, slots_per_epoch: u64) -> bool {
    duties
        .attestation_slot
        .map_or(true, |slot| slot.epoch(slots_per_epoch) == epoch)
        && duties.block_proposal_slots.as_ref().map_or(true, |slots| {
            slots
                .iter()
                .all(|slot| slot.epoch(slots_per_epoch) == epoch)
        })
}
