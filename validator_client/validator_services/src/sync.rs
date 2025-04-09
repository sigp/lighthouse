pub(crate) use crate::duties_service::Error;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slot_clock::SlotClock;
use std::collections::HashMap;
use types::{ChainSpec, EthSpec, PublicKeyBytes, Slot, SyncDuty, SyncSelectionProof, SyncSubnetId};
use validator_store::ValidatorStore;

/// Number of epochs in advance to compute selection proofs when not in `distributed` mode.
pub const AGGREGATION_PRE_COMPUTE_EPOCHS: u64 = 2;
/// Number of slots in advance to compute selection proofs when in `distributed` mode.
pub const AGGREGATION_PRE_COMPUTE_SLOTS_DISTRIBUTED: u64 = 1;

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
    pub fn new(distributed: bool) -> Self {
        Self {
            committees: RwLock::new(HashMap::new()),
            distributed,
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

    /// Number of slots in advance to compute selection proofs
    fn aggregation_pre_compute_slots<E: EthSpec>(&self) -> u64 {
        if self.distributed {
            AGGREGATION_PRE_COMPUTE_SLOTS_DISTRIBUTED
        } else {
            E::slots_per_epoch() * AGGREGATION_PRE_COMPUTE_EPOCHS
        }
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
