use crate::duties_service::{DutiesService, Error, SelectionProofConfig};
use eth2::types::SyncCommitteeSelection;
use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use logging::crit;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, EthSpec, PublicKeyBytes, Slot, SyncDuty, SyncSelectionProof, SyncSubnetId};
use validator_store::{DoppelgangerStatus, Error as ValidatorStoreError, ValidatorStore};

/// Top-level data-structure containing sync duty information.
///
/// This data is structured as a series of nested `HashMap`s wrapped in `RwLock`s. Fine-grained
/// locking is used to provide maximum concurrency for the different services reading and writing.
///
/// Deadlocks are prevented by:
///
/// 1. Hierarchical locking. It is impossible to lock an inner lock (e.g. `validators`) without
///    first locking its parent.
/// 2. One-at-a-time locking. For the innermost locks on the aggregator duties, all of the functions
///    in this file take care to only lock one validator at a time. We never hold a lock while
///    trying to obtain another one (hence no lock ordering issues).
pub struct SyncDutiesMap {
    /// Map from sync committee period to duties for members of that sync committee.
    committees: RwLock<HashMap<u64, CommitteeDuties>>,
    /// Whether we are in `distributed` mode and using reduced lookahead for aggregate pre-compute.
    pub selection_proof_config: SelectionProofConfig,
}

/// Duties for a single sync committee period.
#[derive(Default)]
pub struct CommitteeDuties {
    /// Map from validator index to validator duties.
    ///
    /// A `None` value indicates that the validator index is known *not* to be a member of the sync
    /// committee, while a `Some` indicates a known member. An absent value indicates that the
    /// validator index was not part of the set of local validators when the duties were fetched.
    /// This allows us to track changes to the set of local validators.
    validators: RwLock<HashMap<u64, Option<ValidatorDuties>>>,
}

/// Duties for a single validator.
pub struct ValidatorDuties {
    /// The sync duty: including validator sync committee indices & pubkey.
    duty: SyncDuty,
    /// The aggregator duties: cached selection proofs for upcoming epochs.
    aggregation_duties: AggregatorDuties,
}

/// Aggregator duties for a single validator.
pub struct AggregatorDuties {
    /// The slot up to which aggregation proofs have already been computed (inclusive).
    pre_compute_slot: RwLock<Option<Slot>>,
    /// Map from slot & subnet ID to proof that this validator is an aggregator.
    ///
    /// The slot is the slot at which the signed contribution and proof should be broadcast,
    /// which is 1 less than the slot for which the `duty` was computed.
    proofs: RwLock<HashMap<(Slot, SyncSubnetId), SyncSelectionProof>>,
}

/// Duties for multiple validators, for a single slot.
///
/// This type is returned to the sync service.
pub struct SlotDuties {
    /// List of duties for all sync committee members at this slot.
    ///
    /// Note: this is intentionally NOT split by subnet so that we only sign
    /// one `SyncCommitteeMessage` per validator (recall a validator may be part of multiple
    /// subnets).
    pub duties: Vec<SyncDuty>,
    /// Map from subnet ID to validator index and selection proof of each aggregator.
    pub aggregators: HashMap<SyncSubnetId, Vec<(u64, PublicKeyBytes, SyncSelectionProof)>>,
}

impl SyncDutiesMap {
    pub fn new(selection_proof_config: SelectionProofConfig) -> Self {
        Self {
            committees: RwLock::new(HashMap::new()),
            selection_proof_config,
        }
    }

    /// Check if duties are already known for all of the given validators for `committee_period`.
    fn all_duties_known(&self, committee_period: u64, validator_indices: &[u64]) -> bool {
        self.committees
            .read()
            .get(&committee_period)
            .is_some_and(|committee_duties| {
                let validator_duties = committee_duties.validators.read();
                validator_indices
                    .iter()
                    .all(|index| validator_duties.contains_key(index))
            })
    }

    /// Prepare for pre-computation of selection proofs for `committee_period`.
    ///
    /// Return the slot up to which proofs should be pre-computed, as well as a vec of
    /// `(previous_pre_compute_slot, sync_duty)` pairs for all validators which need to have proofs
    /// computed. See `fill_in_aggregation_proofs` for the actual calculation.
    fn prepare_for_aggregator_pre_compute<E: EthSpec>(
        &self,
        committee_period: u64,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> (Slot, Vec<(Slot, SyncDuty)>) {
        let default_start_slot = std::cmp::max(
            current_slot,
            first_slot_of_period::<E>(committee_period, spec),
        );
        let pre_compute_lookahead_slots = self.selection_proof_config.lookahead_slot;
        let pre_compute_slot = std::cmp::min(
            current_slot + pre_compute_lookahead_slots,
            last_slot_of_period::<E>(committee_period, spec),
        );

        let pre_compute_duties = self.committees.read().get(&committee_period).map_or_else(
            Vec::new,
            |committee_duties| {
                let validator_duties = committee_duties.validators.read();
                validator_duties
                    .values()
                    .filter_map(|maybe_duty| {
                        let duty = maybe_duty.as_ref()?;
                        let old_pre_compute_slot = duty
                            .aggregation_duties
                            .pre_compute_slot
                            .write()
                            .replace(pre_compute_slot);

                        match old_pre_compute_slot {
                            // No proofs pre-computed previously, compute all from the start of
                            // the period or the current slot (whichever is later).
                            None => Some((default_start_slot, duty.duty.clone())),
                            // Proofs computed up to `prev`, start from the subsequent epoch.
                            Some(prev) if prev < pre_compute_slot => {
                                Some((prev + 1, duty.duty.clone()))
                            }
                            // Proofs already known, no need to compute.
                            _ => None,
                        }
                    })
                    .collect()
            },
        );
        (pre_compute_slot, pre_compute_duties)
    }

    fn get_or_create_committee_duties<'a, 'b>(
        &'a self,
        committee_period: u64,
        validator_indices: impl IntoIterator<Item = &'b u64>,
    ) -> MappedRwLockReadGuard<'a, CommitteeDuties> {
        let mut committees_writer = self.committees.write();

        committees_writer
            .entry(committee_period)
            .or_default()
            .init(validator_indices);

        // Return shared reference
        RwLockReadGuard::map(
            RwLockWriteGuard::downgrade(committees_writer),
            |committees_reader| &committees_reader[&committee_period],
        )
    }

    /// Get duties for all validators for the given `wall_clock_slot`.
    ///
    /// This is the entry-point for the sync committee service.
    pub fn get_duties_for_slot<E: EthSpec>(
        &self,
        wall_clock_slot: Slot,
        spec: &ChainSpec,
    ) -> Option<SlotDuties> {
        // Sync duties lag their assigned slot by 1
        let duty_slot = wall_clock_slot + 1;

        let sync_committee_period = duty_slot
            .epoch(E::slots_per_epoch())
            .sync_committee_period(spec)
            .ok()?;

        let committees_reader = self.committees.read();
        let committee_duties = committees_reader.get(&sync_committee_period)?;

        let mut duties = vec![];
        let mut aggregators = HashMap::new();

        committee_duties
            .validators
            .read()
            .values()
            // Filter out non-members & failed subnet IDs.
            .filter_map(|opt_duties| {
                let duty = opt_duties.as_ref()?;
                let subnet_ids = duty.duty.subnet_ids::<E>().ok()?;
                Some((duty, subnet_ids))
            })
            // Add duties for members to the vec of all duties, and aggregators to the
            // aggregators map.
            .for_each(|(validator_duty, subnet_ids)| {
                duties.push(validator_duty.duty.clone());

                let proofs = validator_duty.aggregation_duties.proofs.read();

                for subnet_id in subnet_ids {
                    if let Some(proof) = proofs.get(&(wall_clock_slot, subnet_id)) {
                        aggregators.entry(subnet_id).or_insert_with(Vec::new).push((
                            validator_duty.duty.validator_index,
                            validator_duty.duty.pubkey,
                            proof.clone(),
                        ));
                    }
                }
            });

        Some(SlotDuties {
            duties,
            aggregators,
        })
    }

    /// Prune duties for past sync committee periods from the map.
    fn prune(&self, current_sync_committee_period: u64) {
        self.committees
            .write()
            .retain(|period, _| *period >= current_sync_committee_period)
    }
}

impl CommitteeDuties {
    fn init<'b>(&mut self, validator_indices: impl IntoIterator<Item = &'b u64>) {
        validator_indices.into_iter().for_each(|validator_index| {
            self.validators
                .get_mut()
                .entry(*validator_index)
                .or_insert(None);
        })
    }
}

impl ValidatorDuties {
    fn new(duty: SyncDuty) -> Self {
        Self {
            duty,
            aggregation_duties: AggregatorDuties {
                pre_compute_slot: RwLock::new(None),
                proofs: RwLock::new(HashMap::new()),
            },
        }
    }
}

/// Number of epochs to wait from the start of the period before actually fetching duties.
fn epoch_offset(spec: &ChainSpec) -> u64 {
    spec.epochs_per_sync_committee_period.as_u64() / 2
}

fn first_slot_of_period<E: EthSpec>(sync_committee_period: u64, spec: &ChainSpec) -> Slot {
    (spec.epochs_per_sync_committee_period * sync_committee_period).start_slot(E::slots_per_epoch())
}

fn last_slot_of_period<E: EthSpec>(sync_committee_period: u64, spec: &ChainSpec) -> Slot {
    first_slot_of_period::<E>(sync_committee_period + 1, spec) - 1
}

pub async fn poll_sync_committee_duties<S: ValidatorStore + 'static, T: SlotClock + 'static>(
    duties_service: &Arc<DutiesService<S, T>>,
) -> Result<(), Error<S::Error>> {
    let sync_duties = &duties_service.sync_duties;
    let spec = &duties_service.spec;
    let current_slot = duties_service
        .slot_clock
        .now()
        .ok_or(Error::UnableToReadSlotClock)?;
    let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

    // If the Altair fork is yet to be activated, do not attempt to poll for duties.
    if spec
        .altair_fork_epoch
        .is_none_or(|altair_epoch| current_epoch < altair_epoch)
    {
        return Ok(());
    }

    let current_sync_committee_period = current_epoch.sync_committee_period(spec)?;
    let next_sync_committee_period = current_sync_committee_period + 1;

    // Collect *all* pubkeys, even those undergoing doppelganger protection.
    //
    // Sync committee messages are not slashable and are currently excluded from doppelganger
    // protection.
    let local_pubkeys: HashSet<_> = duties_service
        .validator_store
        .voting_pubkeys(DoppelgangerStatus::ignored);

    let local_indices = {
        let mut local_indices = Vec::with_capacity(local_pubkeys.len());

        for &pubkey in &local_pubkeys {
            if let Some(validator_index) = duties_service.validator_store.validator_index(&pubkey) {
                local_indices.push(validator_index)
            }
        }
        local_indices
    };

    // If duties aren't known for the current period, poll for them.
    if !sync_duties.all_duties_known(current_sync_committee_period, &local_indices) {
        poll_sync_committee_duties_for_period(
            duties_service,
            &local_indices,
            current_sync_committee_period,
        )
        .await?;

        // Prune previous duties (we avoid doing this too often as it locks the whole map).
        sync_duties.prune(current_sync_committee_period);
    }

    // Pre-compute aggregator selection proofs for the current period.
    let (current_pre_compute_slot, new_pre_compute_duties) = sync_duties
        .prepare_for_aggregator_pre_compute::<S::E>(
            current_sync_committee_period,
            current_slot,
            spec,
        );

    if !new_pre_compute_duties.is_empty() {
        let sub_duties_service = duties_service.clone();
        duties_service.executor.spawn(
            async move {
                fill_in_aggregation_proofs(
                    sub_duties_service,
                    &new_pre_compute_duties,
                    current_sync_committee_period,
                    current_slot,
                    current_pre_compute_slot,
                )
                .await
            },
            "duties_service_sync_selection_proofs",
        );
    }

    // If we're past the point in the current period where we should determine duties for the next
    // period and they are not yet known, then poll.
    if current_epoch.as_u64() % spec.epochs_per_sync_committee_period.as_u64() >= epoch_offset(spec)
        && !sync_duties.all_duties_known(next_sync_committee_period, &local_indices)
    {
        poll_sync_committee_duties_for_period(
            duties_service,
            &local_indices,
            next_sync_committee_period,
        )
        .await?;

        // Prune (this is the main code path for updating duties, so we should almost always hit
        // this prune).
        sync_duties.prune(current_sync_committee_period);
    }

    // Pre-compute aggregator selection proofs for the next period.
    let aggregate_pre_compute_lookahead_slots = sync_duties.selection_proof_config.lookahead_slot;
    if (current_slot + aggregate_pre_compute_lookahead_slots)
        .epoch(S::E::slots_per_epoch())
        .sync_committee_period(spec)?
        == next_sync_committee_period
    {
        let (pre_compute_slot, new_pre_compute_duties) = sync_duties
            .prepare_for_aggregator_pre_compute::<S::E>(
                next_sync_committee_period,
                current_slot,
                spec,
            );

        if !new_pre_compute_duties.is_empty() {
            let sub_duties_service = duties_service.clone();
            duties_service.executor.spawn(
                async move {
                    fill_in_aggregation_proofs(
                        sub_duties_service,
                        &new_pre_compute_duties,
                        next_sync_committee_period,
                        current_slot,
                        pre_compute_slot,
                    )
                    .await
                },
                "duties_service_sync_selection_proofs",
            );
        }
    }

    Ok(())
}

pub async fn poll_sync_committee_duties_for_period<S: ValidatorStore, T: SlotClock + 'static>(
    duties_service: &Arc<DutiesService<S, T>>,
    local_indices: &[u64],
    sync_committee_period: u64,
) -> Result<(), Error<S::Error>> {
    let spec = &duties_service.spec;

    // no local validators don't need to poll for sync committee
    if local_indices.is_empty() {
        debug!(
            sync_committee_period,
            "No validators, not polling for sync committee duties"
        );
        return Ok(());
    }

    debug!(
        sync_committee_period,
        num_validators = local_indices.len(),
        "Fetching sync committee duties"
    );

    let period_start_epoch = spec.epochs_per_sync_committee_period * sync_committee_period;

    let duties_response = duties_service
        .beacon_nodes
        .first_success(|beacon_node| async move {
            let _timer = validator_metrics::start_timer_vec(
                &validator_metrics::DUTIES_SERVICE_TIMES,
                &[validator_metrics::VALIDATOR_DUTIES_SYNC_HTTP_POST],
            );
            beacon_node
                .post_validator_duties_sync(period_start_epoch, local_indices)
                .await
        })
        .await;

    let duties = match duties_response {
        Ok(res) => res.data,
        Err(e) => {
            warn!(
                sync_committee_period,
                error = %e,
                "Failed to download sync committee duties"
            );
            return Ok(());
        }
    };

    debug!(count = duties.len(), "Fetched sync duties from BN");

    // Add duties to map.
    let committee_duties = duties_service
        .sync_duties
        .get_or_create_committee_duties(sync_committee_period, local_indices);

    let mut validator_writer = committee_duties.validators.write();
    for duty in duties {
        let validator_duties = validator_writer
            .get_mut(&duty.validator_index)
            .ok_or(Error::SyncDutiesNotFound(duty.validator_index))?;

        let updated = validator_duties.as_ref().is_none_or(|existing_duties| {
            let updated_due_to_reorg = existing_duties.duty.validator_sync_committee_indices
                != duty.validator_sync_committee_indices;
            if updated_due_to_reorg {
                warn!(
                    message = "this could be due to a really long re-org, or a bug",
                    "Sync committee duties changed"
                );
            }
            updated_due_to_reorg
        });

        if updated {
            info!(
                validator_index = duty.validator_index,
                sync_committee_period, "Validator in sync committee"
            );

            *validator_duties = Some(ValidatorDuties::new(duty));
        }
    }

    Ok(())
}

// Create a helper function here to reduce code duplication for normal and distributed mode
pub async fn make_sync_selection_proof<S: ValidatorStore, T: SlotClock>(
    duties_service: &Arc<DutiesService<S, T>>,
    duty: &SyncDuty,
    proof_slot: Slot,
    subnet_id: SyncSubnetId,
) -> Option<SyncSelectionProof> {
    let sync_selection_proof = duties_service
        .validator_store
        .produce_sync_selection_proof(&duty.pubkey, proof_slot, subnet_id)
        .await;

    let selection_proof = match sync_selection_proof {
        Ok(proof) => proof,
        Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
            // A pubkey can be missing when a validator was recently removed via the API
            debug!(
            ?pubkey,
            "slot" = %proof_slot,
            "Missing pubkey for sync selection proof");
            return None;
        }
        Err(e) => {
            warn!(
                "error" = ?e,
                "pubkey" = ?duty.pubkey,
                "slot" = %proof_slot,
                "Unable to sign selection proof"
            );
            return None;
        }
    };

    // In DVT with middleware, when we want to call the selections endpoint
    if duties_service
        .sync_duties
        .selection_proof_config
        .selections_endpoint
    {
        debug!(
            "validator_index" = duty.validator_index,
            "slot" = %proof_slot,
            "subcommittee_index" = *subnet_id,
            // This is partial selection proof
            "partial selection proof" = ?selection_proof,
            "Sending sync selection to middleware"
        );

        let sync_committee_selection = SyncCommitteeSelection {
            validator_index: duty.validator_index,
            slot: proof_slot,
            subcommittee_index: *subnet_id,
            selection_proof: selection_proof.clone().into(),
        };

        // Call the endpoint /eth/v1/validator/sync_committee_selections
        // by sending the SyncCommitteeSelection that contains partial sync selection proof
        // The middleware should return SyncCommitteeSelection that contains full sync selection proof
        let middleware_response = duties_service
            .beacon_nodes
            .first_success(|beacon_node| {
                let selection_data = sync_committee_selection.clone();
                async move {
                    beacon_node
                        .post_validator_sync_committee_selections(&[selection_data])
                        .await
                }
            })
            .await;

        match middleware_response {
            Ok(mut response) => {
                let Some(response_data) = response.data.pop() else {
                    error!(
                        validator_index = duty.validator_index,
                        slot = %proof_slot,
                        "Empty response from sync selection middleware",
                    );
                    return None;
                };
                debug!(
                    "validator_index" = response_data.validator_index,
                    "slot" = %response_data.slot,
                    "subcommittee_index" = response_data.subcommittee_index,
                    // The selection proof from middleware response will be a full selection proof
                    "full selection proof" = ?response_data.selection_proof,
                    "Received sync selection from middleware"
                );

                // Convert the response to a SyncSelectionProof
                let full_selection_proof = SyncSelectionProof::from(response_data.selection_proof);
                Some(full_selection_proof)
            }
            Err(e) => {
                error!(
                    "error" = %e,
                    %proof_slot,
                    "Failed to get sync selection proofs from middleware"
                );
                None
            }
        }
    } else {
        // In non-distributed mode, the selection_proof is already a full selection proof
        Some(selection_proof)
    }
}

pub async fn fill_in_aggregation_proofs<S: ValidatorStore, T: SlotClock + 'static>(
    duties_service: Arc<DutiesService<S, T>>,
    pre_compute_duties: &[(Slot, SyncDuty)],
    sync_committee_period: u64,
    current_slot: Slot,
    pre_compute_slot: Slot,
) {
    // Start at the next slot, as aggregation proofs for the duty at the current slot are no longer
    // required since we do the actual aggregation in the slot before the duty slot.
    let start_slot = current_slot.as_u64() + 1;

    // Generate selection proofs for each validator at each slot, one slot at a time.
    for slot in (start_slot..=pre_compute_slot.as_u64()).map(Slot::new) {
        // For distributed mode
        if duties_service
            .sync_duties
            .selection_proof_config
            .parallel_sign
        {
            let mut futures_unordered = FuturesUnordered::new();

            for (_, duty) in pre_compute_duties {
                let subnet_ids = match duty.subnet_ids::<S::E>() {
                    Ok(subnet_ids) => subnet_ids,
                    Err(e) => {
                        crit!(
                            "error" = ?e,
                            "Arithmetic error computing subnet IDs"
                        );
                        continue;
                    }
                };

                // Construct proof for prior slot.
                let proof_slot = slot - 1;

                // Calling the make_sync_selection_proof will return a full selection proof
                for &subnet_id in &subnet_ids {
                    let duties_service = duties_service.clone();
                    futures_unordered.push(async move {
                        let result =
                            make_sync_selection_proof(&duties_service, duty, proof_slot, subnet_id)
                                .await;

                        result.map(|proof| (duty.validator_index, proof_slot, subnet_id, proof))
                    });
                }
            }

            while let Some(result) = futures_unordered.next().await {
                let Some((validator_index, proof_slot, subnet_id, proof)) = result else {
                    continue;
                };
                let sync_map = duties_service.sync_duties.committees.read();
                let Some(committee_duties) = sync_map.get(&sync_committee_period) else {
                    debug!("period" = sync_committee_period, "Missing sync duties");
                    continue;
                };

                let validators = committee_duties.validators.read();

                // Check if the validator is an aggregator
                match proof.is_aggregator::<S::E>() {
                    Ok(true) => {
                        if let Some(Some(duty)) = validators.get(&validator_index) {
                            debug!(
                                validator_index,
                                "slot" = %proof_slot,
                                "subcommittee_index" = *subnet_id,
                                // log full selection proof for debugging
                                "full selection proof" = ?proof,
                                "Validator is sync aggregator"
                            );

                            // Store the proof
                            duty.aggregation_duties
                                .proofs
                                .write()
                                .insert((proof_slot, subnet_id), proof);
                        }
                    }
                    Ok(false) => {} // Not an aggregator
                    Err(e) => {
                        warn!(
                            validator_index,
                            %slot,
                            "error" = ?e,
                            "Error determining is_aggregator"
                        );
                    }
                }
            }
        } else {
            // For non-distributed mode
            debug!(
                period = sync_committee_period,
                %current_slot,
                %pre_compute_slot,
                "Calculating sync selection proofs"
            );

            let mut validator_proofs = vec![];
            for (validator_start_slot, duty) in pre_compute_duties {
                // Proofs are already known at this slot for this validator.
                if slot < *validator_start_slot {
                    continue;
                }

                let subnet_ids = match duty.subnet_ids::<S::E>() {
                    Ok(subnet_ids) => subnet_ids,
                    Err(e) => {
                        crit!(
                            error = ?e,
                            "Arithmetic error computing subnet IDs"
                        );
                        continue;
                    }
                };

                // Create futures to produce proofs.
                let duties_service_ref = &duties_service;
                let futures = subnet_ids.iter().map(|subnet_id| async move {
                    // Construct proof for prior slot.
                    let proof_slot = slot - 1;

                    let proof =
                        make_sync_selection_proof(duties_service_ref, duty, proof_slot, *subnet_id)
                            .await;

                    match proof {
                        Some(proof) => match proof.is_aggregator::<S::E>() {
                            Ok(true) => {
                                debug!(
                                    validator_index = duty.validator_index,
                                    slot = %proof_slot,
                                    %subnet_id,
                                    "Validator is sync aggregator"
                                );
                                Some(((proof_slot, *subnet_id), proof))
                            }
                            Ok(false) => None,
                            Err(e) => {
                                warn!(
                                    pubkey = ?duty.pubkey,
                                    slot = %proof_slot,
                                    error = ?e,
                                    "Error determining is_aggregator"
                                );
                                None
                            }
                        },

                        None => None,
                    }
                });

                // Execute all the futures in parallel, collecting any successful results.
                let proofs = join_all(futures)
                    .await
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();

                validator_proofs.push((duty.validator_index, proofs));
            }

            // Add to global storage (we add regularly so the proofs can be used ASAP).
            let sync_map = duties_service.sync_duties.committees.read();
            let Some(committee_duties) = sync_map.get(&sync_committee_period) else {
                debug!(period = sync_committee_period, "Missing sync duties");
                continue;
            };
            let validators = committee_duties.validators.read();
            let num_validators_updated = validator_proofs.len();

            for (validator_index, proofs) in validator_proofs {
                if let Some(Some(duty)) = validators.get(&validator_index) {
                    duty.aggregation_duties.proofs.write().extend(proofs);
                } else {
                    debug!(
                        validator_index,
                        period = sync_committee_period,
                        "Missing sync duty to update"
                    );
                }
            }

            if num_validators_updated > 0 {
                debug!(
                    %slot,
                    updated_validators = num_validators_updated,
                    "Finished computing sync selection proofs"
                );
            }
        }
    }
}
