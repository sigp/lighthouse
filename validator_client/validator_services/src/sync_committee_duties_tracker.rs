use parking_lot::{MappedRwLockReadGuard, RwLock};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, EthSpec, Hash256, PublicKeyBytes, Slot, SyncDuty, SyncSelectionProof, SyncSubnetId};
use validator_store::{DoppelgangerStatus, Error as ValidatorStoreError, ValidatorStore};
use beacon_node_fallback::BeaconNodeFallback;
use futures::future::join_all;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::lock_api::RwLockWriteGuard;

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
    distributed: bool,
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
    pub validators: RwLock<HashMap<u64, Option<ValidatorDuties>>>,
}

/// Duties for a single validator.
pub struct ValidatorDuties {
    /// The sync duty: including validator sync committee indices & pubkey.
    pub duty: SyncDuty,
    /// The aggregator duties: cached selection proofs for upcoming epochs.
    pub aggregation_duties: AggregatorDuties,
}

/// Aggregator duties for a single validator.
pub struct AggregatorDuties {
    /// The slot up to which aggregation proofs have already been computed (inclusive).
    pub pre_compute_slot: RwLock<Option<Slot>>,
    /// Map from slot & subnet ID to proof that this validator is an aggregator.
    ///
    /// The slot is the slot at which the signed contribution and proof should be broadcast,
    /// which is 1 less than the slot for which the `duty` was computed.
    pub proofs: RwLock<HashMap<(Slot, SyncSubnetId), SyncSelectionProof>>,
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
    pub fn new(distributed: bool) -> Self {
        Self {
            committees: RwLock::new(HashMap::new()),
            distributed,
        }
    }

    /// Check if duties are already known for all of the given validators for `committee_period`.
    pub fn all_duties_known(&self, committee_period: u64, validator_indices: &[u64]) -> bool {
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

    /// Number of slots in advance to compute selection proofs
    pub fn aggregation_pre_compute_slots<E: EthSpec>(&self) -> u64 {
        const STANDARD_SELECTION_PROOF_SLOT_LOOKAHEAD: u64 = 8;
        const DISTRIBUTED_SELECTION_PROOF_SLOT_LOOKAHEAD: u64 = 1;

        if self.distributed {
            DISTRIBUTED_SELECTION_PROOF_SLOT_LOOKAHEAD
        } else {
            STANDARD_SELECTION_PROOF_SLOT_LOOKAHEAD
        }
    }

    /// Prepare for pre-computation of selection proofs for `committee_period`.
    ///
    /// Return the slot up to which proofs should be pre-computed, as well as a vec of
    /// `(previous_pre_compute_slot, sync_duty)` pairs for all validators which need to have proofs
    /// computed. See `fill_in_aggregation_proofs` for the actual calculation.
    pub fn prepare_for_aggregator_pre_compute<E: EthSpec>(
        &self,
        committee_period: u64,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> (Slot, Vec<(Slot, SyncDuty)>) {
        let default_start_slot = std::cmp::max(
            current_slot,
            first_slot_of_period::<E>(committee_period, spec),
        );
        let pre_compute_lookahead_slots = self.aggregation_pre_compute_slots::<E>();
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

    pub fn get_or_create_committee_duties<'a, 'b>(
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
    pub fn prune(&self, current_sync_committee_period: u64) {
        self.committees
            .write()
            .retain(|period, _| *period >= current_sync_committee_period)
    }
}

impl CommitteeDuties {
    pub fn init<'b>(&mut self, validator_indices: impl IntoIterator<Item = &'b u64>) {
        validator_indices.into_iter().for_each(|validator_index| {
            self.validators
                .get_mut()
                .entry(*validator_index)
                .or_insert(None);
        })
    }
}

impl ValidatorDuties {
    pub fn new(duty: SyncDuty) -> Self {
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

/// First slot of a sync committee period
fn first_slot_of_period<E: EthSpec>(sync_committee_period: u64, spec: &ChainSpec) -> Slot {
    (spec.epochs_per_sync_committee_period * sync_committee_period).start_slot(E::slots_per_epoch())
}

/// Last slot of a sync committee period
fn last_slot_of_period<E: EthSpec>(sync_committee_period: u64, spec: &ChainSpec) -> Slot {
    let next_period = sync_committee_period + 1;
    first_slot_of_period::<E>(next_period, spec) - 1
}

/// Error type for sync committee duty operations
#[derive(Debug)]
pub enum Error {
    UnableToReadSlotClock,
    SyncDutiesNotFound(#[allow(dead_code)] u64),
    // Add other error types as needed
}

/// Tracks sync committee duties and manages their lifecycle.
pub struct SyncCommitteeDutiesTracker<T: SlotClock + 'static> {
    /// Map from validator index to sync committee duties.
    pub sync_duties: SyncDutiesMap,
    /// Provides HTTP access to remote beacon nodes.
    pub beacon_nodes: Arc<BeaconNodeFallback<T>>,
    /// The runtime for spawning tasks.
    pub executor: TaskExecutor,
    /// The current chain spec.
    pub spec: Arc<ChainSpec>,
    /// Tracks the current slot.
    pub slot_clock: T,
    /// If this validator is running in distributed mode.
    pub distributed: bool,
    /// Whether to disable attestation and sync committee duties
    pub disable_attesting: bool,
}

impl<T: SlotClock + 'static> SyncCommitteeDutiesTracker<T> {
    pub fn new(
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        spec: Arc<ChainSpec>,
        slot_clock: T,
        distributed: bool,
    ) -> Self {
        Self {
            sync_duties: SyncDutiesMap::new(distributed),
            beacon_nodes,
            executor,
            spec,
            slot_clock,
            distributed,
            disable_attesting: false,
        }
    }

    /// Start a service that periodically updates the sync committee duties
    pub fn start_update_service<S: ValidatorStore + 'static>(
        self: &Arc<Self>,
        validator_store: Arc<S>,
    ) {
        let tracker = self.clone();
        
        self.executor.spawn(
            async move {
                loop {
                    if let Err(e) = tracker.poll_sync_committee_duties(validator_store.clone()).await {
                        error!(
                            error = ?e,
                           "Failed to poll sync committee duties"
                        );
                    }

                    // Wait until the next slot before polling again.
                    if let Some(duration) = tracker.slot_clock.duration_to_next_slot() {
                        sleep(duration).await;
                    } else {
                        // Just sleep for one slot if we are unable to read the system clock
                        sleep(tracker.slot_clock.slot_duration()).await;
                        continue;
                    }
                }
            },
            "sync_committee_duties_tracker",
        );
    }

    /// Access to the sync duties map
    pub fn sync_duties(&self) -> &SyncDutiesMap {
        &self.sync_duties
    }

    /// Number of epochs to wait from the start of the period before actually fetching duties.
    fn epoch_offset(&self) -> u64 {
        self.spec.epochs_per_sync_committee_period.as_u64() / 2
    }

    /// First slot of a sync committee period
    fn first_slot_of_period<S: EthSpec>(&self, sync_committee_period: u64) -> Slot {
        (self.spec.epochs_per_sync_committee_period * sync_committee_period).start_slot(S::slots_per_epoch())
    }

    /// Last slot of a sync committee period
    fn last_slot_of_period<S: EthSpec>(&self, sync_committee_period: u64) -> Slot {
        let next_period = sync_committee_period + 1;
        self.first_slot_of_period::<S>(next_period) - 1
    }

    /// Poll for sync committee duties and update the duty store
    async fn poll_sync_committee_duties<S: ValidatorStore + 'static>(
        self: &Arc<Self>,
        validator_store: Arc<S>,
    ) -> Result<(), crate::sync::Error<S::Error>> {
        let current_slot = self.slot_clock
            .now()
            .ok_or(crate::sync::Error::UnableToReadSlotClock)?;
        let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

        // If the Altair fork is yet to be activated, do not attempt to poll for duties.
        if self.spec
            .altair_fork_epoch
            .is_none_or(|altair_epoch| current_epoch < altair_epoch)
        {
            return Ok(());
        }

        // Collect *all* pubkeys, even those undergoing doppelganger protection.
        let local_pubkeys: HashSet<_> = validator_store
            .voting_pubkeys(DoppelgangerStatus::ignored);

        let local_indices = {
            let mut local_indices = Vec::with_capacity(local_pubkeys.len());

            for &pubkey in &local_pubkeys {
                if let Some(validator_index) = validator_store.validator_index(&pubkey) {
                    local_indices.push(validator_index)
                }
            }
            local_indices
        };

        let current_sync_committee_period = current_epoch.sync_committee_period(&self.spec)?;
        let next_sync_committee_period = current_sync_committee_period + 1;

        // If duties aren't known for the current period, poll for them.
        if !self.sync_duties.all_duties_known(current_sync_committee_period, &local_indices) {
            self.poll_sync_committee_duties_for_period(
                &validator_store,
                &local_indices,
                current_sync_committee_period,
            )
            .await?;

            // Prune previous duties (we avoid doing this too often as it locks the whole map).
            self.sync_duties.prune(current_sync_committee_period);
        }

        // Pre-compute aggregator selection proofs for the current period.
        let (current_pre_compute_slot, new_pre_compute_duties) = self.sync_duties
            .prepare_for_aggregator_pre_compute::<S::E>(
                current_sync_committee_period,
                current_slot,
                &self.spec,
            );

        if !new_pre_compute_duties.is_empty() {
            let tracker = self.clone();
            let validator_store_clone = validator_store.clone();
            self.executor.spawn(
                async move {
                    tracker.fill_in_aggregation_proofs(
                        validator_store_clone,
                        &new_pre_compute_duties,
                        current_sync_committee_period,
                        current_slot,
                        current_pre_compute_slot,
                    )
                    .await
                },
                "sync_committee_tracker_selection_proofs",
            );
        }

        // If we're past the point in the current period where we should determine duties for the next
        // period and they are not yet known, then poll.
        if current_epoch.as_u64() % self.spec.epochs_per_sync_committee_period.as_u64() >= self.epoch_offset()
            && !self.sync_duties.all_duties_known(next_sync_committee_period, &local_indices)
        {
            self.poll_sync_committee_duties_for_period(
                &validator_store,
                &local_indices,
                next_sync_committee_period,
            )
            .await?;

            // Prune (this is the main code path for updating duties, so we should almost always hit
            // this prune).
            self.sync_duties.prune(current_sync_committee_period);
        }

        // Pre-compute aggregator selection proofs for the next period.
        let aggregate_pre_compute_lookahead_slots = self.sync_duties.aggregation_pre_compute_slots::<S::E>();
        if (current_slot + aggregate_pre_compute_lookahead_slots)
            .epoch(S::E::slots_per_epoch())
            .sync_committee_period(&self.spec)?
            == next_sync_committee_period
        {
            let (pre_compute_slot, new_pre_compute_duties) = self.sync_duties
                .prepare_for_aggregator_pre_compute::<S::E>(
                    next_sync_committee_period,
                    current_slot,
                    &self.spec,
                );

            if !new_pre_compute_duties.is_empty() {
                let tracker = self.clone();
                let validator_store_clone = validator_store.clone();
                self.executor.spawn(
                    async move {
                        tracker.fill_in_aggregation_proofs(
                            validator_store_clone,
                            &new_pre_compute_duties,
                            next_sync_committee_period,
                            current_slot,
                            pre_compute_slot,
                        )
                        .await
                    },
                    "sync_committee_tracker_selection_proofs",
                );
            }
        }

        Ok(())
    }

    /// Poll for sync committee duties for a specific period
    async fn poll_sync_committee_duties_for_period<S: ValidatorStore + 'static>(
        &self,
        validator_store: &Arc<S>,
        local_indices: &[u64],
        sync_committee_period: u64,
    ) -> Result<(), crate::sync::Error<S::Error>> {
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

        let period_start_epoch = self.spec.epochs_per_sync_committee_period * sync_committee_period;

        let duties_response = self.beacon_nodes
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
        let committee_duties = self.sync_duties
            .get_or_create_committee_duties(sync_committee_period, local_indices);

        let mut validator_writer = committee_duties.validators.write();
        for duty in duties {
            let validator_duties = validator_writer
                .get_mut(&duty.validator_index)
                .ok_or(crate::sync::Error::SyncDutiesNotFound(duty.validator_index))?;

            let updated = validator_duties.as_ref().is_none_or(|existing_duties| {
                let updated_due_to_reorg = existing_duties.duty.validator_sync_committee_indices
                    != duty.validator_sync_committee_indices;
                if updated_due_to_reorg {
                    warn!(
                        message = "this could be due to a really long re-org, or a bug",
                        validator_index = duty.validator_index,
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

    /// Fill in aggregation proofs for sync committee duties
    async fn fill_in_aggregation_proofs<S: ValidatorStore + 'static>(
        &self,
        validator_store: Arc<S>,
        pre_compute_duties: &[(Slot, SyncDuty)],
        sync_committee_period: u64,
        current_slot: Slot,
        pre_compute_slot: Slot,
    ) {
        debug!(
            period = sync_committee_period,
            %current_slot,
            %pre_compute_slot,
            "Calculating sync selection proofs"
        );

        // Generate selection proofs for each validator at each slot, one slot at a time.
        for slot in (current_slot.as_u64()..=pre_compute_slot.as_u64()).map(Slot::new) {
            let mut validator_proofs = vec![];
            for (validator_start_slot, duty) in pre_compute_duties {
                // Proofs are already known at this slot for this validator.
                if slot < *validator_start_slot {
                    continue;
                }

                let subnet_ids = match duty.subnet_ids::<S::E>() {
                    Ok(subnet_ids) => subnet_ids,
                    Err(e) => {
                        warn!(
                            pubkey = ?duty.pubkey,
                            slot = %slot,
                            error = ?e,
                            "Error computing subnet IDs"
                        );
                        continue;
                    }
                };

                // Generate proofs in parallel for all subnets.
                let futures = subnet_ids.into_iter().map(|subnet_id| {
                    let validator_store = validator_store.clone();
                    let duty_clone = duty.clone();
                    let proof_slot = slot;

                    async move {
                        match validator_store
                            .produce_sync_selection_proof(&duty_clone.pubkey, proof_slot, subnet_id)
                            .await
                        {
                            Ok(proof) => match proof.is_aggregator::<S::E>() {
                                Ok(true) => {
                                    debug!(
                                        pubkey = ?duty_clone.pubkey,
                                        validator_index = duty_clone.validator_index,
                                        slot = %proof_slot,
                                        %subnet_id,
                                        "Validator is sync aggregator"
                                    );
                                    Some(((proof_slot, subnet_id), proof))
                                }
                                Ok(false) => None,
                                Err(e) => {
                                    warn!(
                                        pubkey = ?duty_clone.pubkey,
                                        slot = %proof_slot,
                                        error = ?e,
                                        "Error determining is_aggregator"
                                    );
                                    None
                                }
                            },
                            Err(e) => {
                                warn!(
                                    pubkey = ?duty_clone.pubkey,
                                    slot = %proof_slot,
                                    error = ?e,
                                    "Error producing sync selection proof"
                                );
                                None
                            }
                        }
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
            let sync_map = self.sync_duties.committees.read();
            let Some(committee_duties) = sync_map.get(&sync_committee_period) else {
                debug!(period = sync_committee_period, "Missing sync duties");
                continue;
            };
            let validators = committee_duties.validators.read();
            let num_validators_updated = validator_proofs.len();

            for (validator_index, proofs) in validator_proofs {
                if let Some(Some(duty)) = validators.get(&validator_index) {
                    let mut aggregator_proofs = duty.aggregation_duties.proofs.write();
                    for ((slot, subnet), proof) in proofs {
                        aggregator_proofs.insert((slot, subnet), proof);
                    }
                }
            }

            debug!(
                period = sync_committee_period,
                num_validators = num_validators_updated,
                slot = %slot,
                "Updated selection proofs"
            );
        }
    }
}
