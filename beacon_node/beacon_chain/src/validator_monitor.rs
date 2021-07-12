//! Provides detailed logging and metrics for a set of registered validators.
//!
//! This component should not affect consensus.

use crate::metrics;
use parking_lot::RwLock;
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_epoch_processing::{
    errors::EpochProcessingError, EpochProcessingSummary,
};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io;
use std::marker::PhantomData;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::{
    AttestationData, AttesterSlashing, BeaconBlockRef, BeaconState, ChainSpec, Epoch, EthSpec,
    Hash256, IndexedAttestation, ProposerSlashing, PublicKeyBytes, SignedAggregateAndProof, Slot,
    VoluntaryExit,
};

/// The validator monitor collects per-epoch data about each monitored validator. Historical data
/// will be kept around for `HISTORIC_EPOCHS` before it is pruned.
pub const HISTORIC_EPOCHS: usize = 4;

#[derive(Debug)]
pub enum Error {
    InvalidPubkey(String),
    FileError(io::Error),
    InvalidUtf8(Utf8Error),
}

/// Contains data pertaining to one validator for one epoch.
#[derive(Default)]
struct EpochSummary {
    /*
     * Attestations with a target in the current epoch.
     */
    /// The number of attestations seen.
    pub attestations: usize,
    /// The delay between when the attestation should have been produced and when it was observed.
    pub attestation_min_delay: Option<Duration>,
    /// The number of times a validators attestation was seen in an aggregate.
    pub attestation_aggregate_incusions: usize,
    /// The number of times a validators attestation was seen in a block.
    pub attestation_block_inclusions: usize,
    /// The minimum observed inclusion distance for an attestation for this epoch..
    pub attestation_min_block_inclusion_distance: Option<Slot>,
    /*
     * Blocks with a slot in the current epoch.
     */
    /// The number of blocks observed.
    pub blocks: usize,
    /// The delay between when the block should have been produced and when it was observed.
    pub block_min_delay: Option<Duration>,
    /*
     * Aggregates with a target in the current epoch
     */
    /// The number of signed aggregate and proofs observed.
    pub aggregates: usize,
    /// The delay between when the aggregate should have been produced and when it was observed.
    pub aggregate_min_delay: Option<Duration>,
    /*
     * Others pertaining to this epoch.
     */
    /// The number of voluntary exists observed.
    pub exits: usize,
    /// The number of proposer slashings observed.
    pub proposer_slashings: usize,
    /// The number of attester slashings observed.
    pub attester_slashings: usize,
}

impl EpochSummary {
    /// Update `current` if:
    ///
    /// - It is `None`.
    /// - `new` is greater than its current value.
    fn update_if_lt<T: Ord>(current: &mut Option<T>, new: T) {
        if let Some(ref mut current) = current {
            if new < *current {
                *current = new
            }
        } else {
            *current = Some(new)
        }
    }

    pub fn register_unaggregated_attestation(&mut self, delay: Duration) {
        self.attestations += 1;
        Self::update_if_lt(&mut self.attestation_min_delay, delay);
    }

    pub fn register_aggregated_attestation(&mut self, delay: Duration) {
        self.aggregates += 1;
        Self::update_if_lt(&mut self.aggregate_min_delay, delay);
    }

    pub fn register_aggregate_attestation_inclusion(&mut self) {
        self.attestation_aggregate_incusions += 1;
    }

    pub fn register_attestation_block_inclusion(&mut self, delay: Slot) {
        self.attestation_block_inclusions += 1;
        Self::update_if_lt(&mut self.attestation_min_block_inclusion_distance, delay);
    }

    pub fn register_exit(&mut self) {
        self.exits += 1;
    }

    pub fn register_proposer_slashing(&mut self) {
        self.proposer_slashings += 1;
    }

    pub fn register_attester_slashing(&mut self) {
        self.attester_slashings += 1;
    }
}

type SummaryMap = HashMap<Epoch, EpochSummary>;

/// A validator that is being monitored by the `ValidatorMonitor`.
struct MonitoredValidator {
    /// A human-readable identifier for the validator.
    pub id: String,
    /// The validator voting pubkey.
    pub pubkey: PublicKeyBytes,
    /// The validator index in the state.
    pub index: Option<u64>,
    /// A history of the validator over time.
    pub summaries: RwLock<SummaryMap>,
}

impl MonitoredValidator {
    fn new(pubkey: PublicKeyBytes, index: Option<u64>) -> Self {
        Self {
            id: index
                .map(|i| i.to_string())
                .unwrap_or_else(|| pubkey.to_string()),
            pubkey,
            index,
            summaries: <_>::default(),
        }
    }

    fn set_index(&mut self, validator_index: u64) {
        if self.index.is_none() {
            self.index = Some(validator_index);
            self.id = validator_index.to_string();
        }
    }

    /// Maps `func` across the `self.summaries`.
    ///
    /// ## Warning
    ///
    /// It is possible to deadlock this function by trying to obtain a lock on
    /// `self.summary` inside `func`.
    ///
    /// ## Notes
    ///
    /// - If `epoch` doesn't exist in `self.summaries`, it is created.
    /// - `self.summaries` may be pruned after `func` is run.
    fn with_epoch_summary<F>(&self, epoch: Epoch, func: F)
    where
        F: Fn(&mut EpochSummary),
    {
        let mut summaries = self.summaries.write();

        func(summaries.entry(epoch).or_default());

        // Prune
        while summaries.len() > HISTORIC_EPOCHS {
            if let Some(key) = summaries.iter().map(|(epoch, _)| *epoch).min() {
                summaries.remove(&key);
            }
        }
    }
}

/// Holds a collection of `MonitoredValidator` and is notified about a variety of events on the P2P
/// network, HTTP API and `BeaconChain`.
///
/// If any of the events pertain to a `MonitoredValidator`, additional logging and metrics will be
/// performed.
///
/// The intention of this struct is to provide users with more logging and Prometheus metrics around
/// validators that they are interested in.
pub struct ValidatorMonitor<T> {
    /// The validators that require additional monitoring.
    validators: HashMap<PublicKeyBytes, MonitoredValidator>,
    /// A map of validator index (state.validators) to a validator public key.
    indices: HashMap<u64, PublicKeyBytes>,
    /// If true, allow the automatic registration of validators.
    auto_register: bool,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ValidatorMonitor<T> {
    pub fn new(pubkeys: Vec<PublicKeyBytes>, auto_register: bool, log: Logger) -> Self {
        let mut s = Self {
            validators: <_>::default(),
            indices: <_>::default(),
            auto_register,
            log,
            _phantom: PhantomData,
        };
        for pubkey in pubkeys {
            s.add_validator_pubkey(pubkey)
        }
        s
    }

    /// Add some validators to `self` for additional monitoring.
    fn add_validator_pubkey(&mut self, pubkey: PublicKeyBytes) {
        let index_opt = self
            .indices
            .iter()
            .find(|(_, candidate_pk)| **candidate_pk == pubkey)
            .map(|(index, _)| *index);

        let log = self.log.clone();
        self.validators.entry(pubkey).or_insert_with(|| {
            info!(
                log,
                "Started monitoring validator";
                "pubkey" => %pubkey,
            );
            MonitoredValidator::new(pubkey, index_opt)
        });
    }

    /// Reads information from the given `state`. The `state` *must* be valid (i.e, able to be
    /// imported).
    pub fn process_valid_state(&mut self, current_epoch: Epoch, state: &BeaconState<T>) {
        // Add any new validator indices.
        state
            .validators()
            .iter()
            .enumerate()
            .skip(self.indices.len())
            .for_each(|(i, validator)| {
                let i = i as u64;
                if let Some(validator) = self.validators.get_mut(&validator.pubkey) {
                    validator.set_index(i)
                }
                self.indices.insert(i, validator.pubkey);
            });

        // Update metrics for individual validators.
        for monitored_validator in self.validators.values() {
            if let Some(i) = monitored_validator.index {
                let i = i as usize;
                let id = &monitored_validator.id;

                if let Some(balance) = state.balances().get(i) {
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_BALANCE_GWEI,
                        &[id],
                        *balance as i64,
                    );
                }

                if let Some(validator) = state.validators().get(i) {
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_EFFECTIVE_BALANCE_GWEI,
                        &[id],
                        u64_to_i64(validator.effective_balance),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_SLASHED,
                        &[id],
                        if validator.slashed { 1 } else { 0 },
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_ACTIVE,
                        &[id],
                        if validator.is_active_at(current_epoch) {
                            1
                        } else {
                            0
                        },
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_EXITED,
                        &[id],
                        if validator.is_exited_at(current_epoch) {
                            1
                        } else {
                            0
                        },
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_WITHDRAWABLE,
                        &[id],
                        if validator.is_withdrawable_at(current_epoch) {
                            1
                        } else {
                            0
                        },
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_ACTIVATION_ELIGIBILITY_EPOCH,
                        &[id],
                        u64_to_i64(validator.activation_eligibility_epoch),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_ACTIVATION_EPOCH,
                        &[id],
                        u64_to_i64(validator.activation_epoch),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_EXIT_EPOCH,
                        &[id],
                        u64_to_i64(validator.exit_epoch),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_WITHDRAWABLE_EPOCH,
                        &[id],
                        u64_to_i64(validator.withdrawable_epoch),
                    );
                }
            }
        }
    }

    pub fn process_validator_statuses(
        &self,
        epoch: Epoch,
        summary: &EpochProcessingSummary,
        spec: &ChainSpec,
    ) -> Result<(), EpochProcessingError> {
        for monitored_validator in self.validators.values() {
            // We subtract two from the state of the epoch that generated these summaries.
            //
            // - One to account for it being the previous epoch.
            // - One to account for the state advancing an epoch whilst generating the validator
            //     statuses.
            let prev_epoch = epoch - 2;
            if let Some(i) = monitored_validator.index {
                let i = i as usize;
                let id = &monitored_validator.id;

                /*
                 * These metrics are reflected differently between Base and Altair.
                 *
                 * For Base, any attestation that is included on-chain will match the source.
                 *
                 * However, in Altair, only attestations that are "timely" are registered as
                 * matching the source.
                 */

                let previous_epoch_active = summary.is_active_unslashed_in_previous_epoch(i);
                let previous_epoch_matched_source = summary.is_previous_epoch_source_attester(i)?;
                let previous_epoch_matched_target = summary.is_previous_epoch_target_attester(i)?;
                let previous_epoch_matched_head = summary.is_previous_epoch_head_attester(i)?;
                let previous_epoch_matched_any = previous_epoch_matched_source
                    || previous_epoch_matched_target
                    || previous_epoch_matched_head;

                if !previous_epoch_active {
                    // Monitored validator is not active, due to awaiting activation
                    // or being exited/withdrawn. Do not attempt to report on its
                    // attestations.
                    continue;
                }

                // Indicates if any attestation made it on-chain.
                //
                // For Base states, this will be *any* attestation whatsoever. For Altair states,
                // this will be any attestation that matched a "timely" flag.
                if previous_epoch_matched_any {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_HIT,
                        &[id],
                    );
                    info!(
                        self.log,
                        "Previous epoch attestation success";
                        "matched_target" => previous_epoch_matched_target,
                        "matched_head" => previous_epoch_matched_head,
                        "epoch" => prev_epoch,
                        "validator" => id,

                    )
                } else {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_MISS,
                        &[id],
                    );
                    error!(
                        self.log,
                        "Previous epoch attestation missing";
                        "epoch" => prev_epoch,
                        "validator" => id,
                    )
                }

                // Indicates if any on-chain attestation hit the head.
                if previous_epoch_matched_head {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_HEAD_ATTESTER_HIT,
                        &[id],
                    );
                } else {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_HEAD_ATTESTER_MISS,
                        &[id],
                    );
                    warn!(
                        self.log,
                        "Attested to an incorrect head";
                        "epoch" => prev_epoch,
                        "validator" => id,
                    );
                }

                // Indicates if any on-chain attestation hit the target.
                if previous_epoch_matched_target {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_TARGET_ATTESTER_HIT,
                        &[id],
                    );
                } else {
                    metrics::inc_counter_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_TARGET_ATTESTER_MISS,
                        &[id],
                    );
                    warn!(
                        self.log,
                        "Attested to an incorrect target";
                        "epoch" => prev_epoch,
                        "validator" => id,
                    );
                }

                // For pre-Altair, state the inclusion distance. This information is not retained in
                // the Altair state.
                if let Some(inclusion_info) = summary.previous_epoch_inclusion_info(i) {
                    if inclusion_info.delay > spec.min_attestation_inclusion_delay {
                        warn!(
                            self.log,
                            "Sub-optimal inclusion delay";
                            "optimal" => spec.min_attestation_inclusion_delay,
                            "delay" => inclusion_info.delay,
                            "epoch" => prev_epoch,
                            "validator" => id,
                        );
                    }

                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_INCLUSION_DISTANCE,
                        &[id],
                        inclusion_info.delay as i64,
                    );
                }
            }
        }

        Ok(())
    }

    fn get_validator_id(&self, validator_index: u64) -> Option<&str> {
        self.indices
            .get(&validator_index)
            .and_then(|pubkey| self.validators.get(pubkey))
            .map(|validator| validator.id.as_str())
    }

    fn get_validator(&self, validator_index: u64) -> Option<&MonitoredValidator> {
        self.indices
            .get(&validator_index)
            .and_then(|pubkey| self.validators.get(pubkey))
    }

    /// Returns the number of validators monitored by `self`.
    pub fn num_validators(&self) -> usize {
        self.validators.len()
    }

    /// If `self.auto_register == true`, add the `validator_index` to `self.monitored_validators`.
    /// Otherwise, do nothing.
    pub fn auto_register_local_validator(&mut self, validator_index: u64) {
        if !self.auto_register {
            return;
        }

        if let Some(pubkey) = self.indices.get(&validator_index) {
            if !self.validators.contains_key(pubkey) {
                info!(
                    self.log,
                    "Started monitoring validator";
                    "pubkey" => %pubkey,
                    "validator" => %validator_index,
                );

                self.validators.insert(
                    *pubkey,
                    MonitoredValidator::new(*pubkey, Some(validator_index)),
                );
            }
        }
    }

    /// Process a block received on gossip.
    pub fn register_gossip_block<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        block: BeaconBlockRef<'_, T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        self.register_beacon_block("gossip", seen_timestamp, block, block_root, slot_clock)
    }

    /// Process a block received on the HTTP API from a local validator.
    pub fn register_api_block<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        block: BeaconBlockRef<'_, T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        self.register_beacon_block("api", seen_timestamp, block, block_root, slot_clock)
    }

    fn register_beacon_block<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        block: BeaconBlockRef<'_, T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        if let Some(id) = self.get_validator_id(block.proposer_index()) {
            let delay = get_block_delay_ms(seen_timestamp, block, slot_clock);

            metrics::inc_counter_vec(&metrics::VALIDATOR_MONITOR_BEACON_BLOCK_TOTAL, &[src, id]);
            metrics::observe_timer_vec(
                &metrics::VALIDATOR_MONITOR_BEACON_BLOCK_DELAY_SECONDS,
                &[src, id],
                delay,
            );

            info!(
                self.log,
                "Block from API";
                "root" => ?block_root,
                "delay" => %delay.as_millis(),
                "slot" => %block.slot(),
                "src" => src,
                "validator" => %id,
            );
        }
    }

    /// Returns the duration between when the attestation `data` could be produced (1/3rd through
    /// the slot) and `seen_timestamp`.
    fn get_unaggregated_attestation_delay_ms<S: SlotClock>(
        seen_timestamp: Duration,
        data: &AttestationData,
        slot_clock: &S,
    ) -> Duration {
        slot_clock
            .start_of(data.slot)
            .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
            .and_then(|gross_delay| {
                gross_delay.checked_sub(slot_clock.unagg_attestation_production_delay())
            })
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    /// Register an attestation seen on the gossip network.
    pub fn register_gossip_unaggregated_attestation<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        self.register_unaggregated_attestation(
            "gossip",
            seen_timestamp,
            indexed_attestation,
            slot_clock,
        )
    }

    /// Register an attestation seen on the HTTP API.
    pub fn register_api_unaggregated_attestation<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        self.register_unaggregated_attestation(
            "api",
            seen_timestamp,
            indexed_attestation,
            slot_clock,
        )
    }

    fn register_unaggregated_attestation<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        let data = &indexed_attestation.data;
        let epoch = data.slot.epoch(T::slots_per_epoch());
        let delay = Self::get_unaggregated_attestation_delay_ms(seen_timestamp, data, slot_clock);

        indexed_attestation.attesting_indices.iter().for_each(|i| {
            if let Some(validator) = self.get_validator(*i) {
                let id = &validator.id;

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_UNAGGREGATED_ATTESTATION_TOTAL,
                    &[src, id],
                );
                metrics::observe_timer_vec(
                    &metrics::VALIDATOR_MONITOR_UNAGGREGATED_ATTESTATION_DELAY_SECONDS,
                    &[src, id],
                    delay,
                );

                info!(
                    self.log,
                    "Unaggregated attestation";
                    "head" => ?data.beacon_block_root,
                    "index" => %data.index,
                    "delay_ms" => %delay.as_millis(),
                    "epoch" => %epoch,
                    "slot" => %data.slot,
                    "src" => src,
                    "validator" => %id,
                );

                validator.with_epoch_summary(epoch, |summary| {
                    summary.register_unaggregated_attestation(delay)
                });
            }
        })
    }

    /// Returns the duration between when a `AggregateAndproof` with `data` could be produced (2/3rd
    /// through the slot) and `seen_timestamp`.
    fn get_aggregated_attestation_delay_ms<S: SlotClock>(
        seen_timestamp: Duration,
        data: &AttestationData,
        slot_clock: &S,
    ) -> Duration {
        slot_clock
            .start_of(data.slot)
            .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
            .and_then(|gross_delay| {
                gross_delay.checked_sub(slot_clock.agg_attestation_production_delay())
            })
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    /// Register a `signed_aggregate_and_proof` seen on the gossip network.
    pub fn register_gossip_aggregated_attestation<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        signed_aggregate_and_proof: &SignedAggregateAndProof<T>,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        self.register_aggregated_attestation(
            "gossip",
            seen_timestamp,
            signed_aggregate_and_proof,
            indexed_attestation,
            slot_clock,
        )
    }

    /// Register a `signed_aggregate_and_proof` seen on the HTTP API.
    pub fn register_api_aggregated_attestation<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        signed_aggregate_and_proof: &SignedAggregateAndProof<T>,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        self.register_aggregated_attestation(
            "api",
            seen_timestamp,
            signed_aggregate_and_proof,
            indexed_attestation,
            slot_clock,
        )
    }

    fn register_aggregated_attestation<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        signed_aggregate_and_proof: &SignedAggregateAndProof<T>,
        indexed_attestation: &IndexedAttestation<T>,
        slot_clock: &S,
    ) {
        let data = &indexed_attestation.data;
        let epoch = data.slot.epoch(T::slots_per_epoch());
        let delay = Self::get_aggregated_attestation_delay_ms(seen_timestamp, data, slot_clock);

        let aggregator_index = signed_aggregate_and_proof.message.aggregator_index;
        if let Some(validator) = self.get_validator(aggregator_index) {
            let id = &validator.id;

            metrics::inc_counter_vec(
                &metrics::VALIDATOR_MONITOR_AGGREGATED_ATTESTATION_TOTAL,
                &[src, id],
            );
            metrics::observe_timer_vec(
                &metrics::VALIDATOR_MONITOR_AGGREGATED_ATTESTATION_DELAY_SECONDS,
                &[src, id],
                delay,
            );

            info!(
                self.log,
                "Aggregated attestation";
                "head" => ?data.beacon_block_root,
                "index" => %data.index,
                "delay_ms" => %delay.as_millis(),
                "epoch" => %epoch,
                "slot" => %data.slot,
                "src" => src,
                "validator" => %id,
            );

            validator.with_epoch_summary(epoch, |summary| {
                summary.register_aggregated_attestation(delay)
            });
        }

        indexed_attestation.attesting_indices.iter().for_each(|i| {
            if let Some(validator) = self.get_validator(*i) {
                let id = &validator.id;

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_ATTESTATION_IN_AGGREGATE_TOTAL,
                    &[src, id],
                );
                metrics::observe_timer_vec(
                    &metrics::VALIDATOR_MONITOR_ATTESTATION_IN_AGGREGATE_DELAY_SECONDS,
                    &[src, id],
                    delay,
                );

                info!(
                    self.log,
                    "Attestation included in aggregate";
                    "head" => ?data.beacon_block_root,
                    "index" => %data.index,
                    "delay_ms" => %delay.as_millis(),
                    "epoch" => %epoch,
                    "slot" => %data.slot,
                    "src" => src,
                    "validator" => %id,
                );

                validator.with_epoch_summary(epoch, |summary| {
                    summary.register_aggregate_attestation_inclusion()
                });
            }
        })
    }

    /// Register that the `indexed_attestation` was included in a *valid* `BeaconBlock`.
    pub fn register_attestation_in_block(
        &self,
        indexed_attestation: &IndexedAttestation<T>,
        block: BeaconBlockRef<'_, T>,
        spec: &ChainSpec,
    ) {
        let data = &indexed_attestation.data;
        let delay = (block.slot() - data.slot) - spec.min_attestation_inclusion_delay;
        let epoch = data.slot.epoch(T::slots_per_epoch());

        indexed_attestation.attesting_indices.iter().for_each(|i| {
            if let Some(validator) = self.get_validator(*i) {
                let id = &validator.id;

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_ATTESTATION_IN_BLOCK_TOTAL,
                    &["block", id],
                );
                metrics::set_int_gauge(
                    &metrics::VALIDATOR_MONITOR_ATTESTATION_IN_BLOCK_DELAY_SLOTS,
                    &["block", id],
                    delay.as_u64() as i64,
                );

                info!(
                    self.log,
                    "Attestation included in block";
                    "head" => ?data.beacon_block_root,
                    "index" => %data.index,
                    "inclusion_lag" => format!("{} slot(s)", delay),
                    "epoch" => %epoch,
                    "slot" => %data.slot,
                    "validator" => %id,
                );

                validator.with_epoch_summary(epoch, |summary| {
                    summary.register_attestation_block_inclusion(delay)
                });
            }
        })
    }

    /// Register an exit from the gossip network.
    pub fn register_gossip_voluntary_exit(&self, exit: &VoluntaryExit) {
        self.register_voluntary_exit("gossip", exit)
    }

    /// Register an exit from the HTTP API.
    pub fn register_api_voluntary_exit(&self, exit: &VoluntaryExit) {
        self.register_voluntary_exit("api", exit)
    }

    /// Register an exit included in a *valid* beacon block.
    pub fn register_block_voluntary_exit(&self, exit: &VoluntaryExit) {
        self.register_voluntary_exit("block", exit)
    }

    fn register_voluntary_exit(&self, src: &str, exit: &VoluntaryExit) {
        if let Some(validator) = self.get_validator(exit.validator_index) {
            let id = &validator.id;
            let epoch = exit.epoch;

            metrics::inc_counter_vec(&metrics::VALIDATOR_MONITOR_EXIT_TOTAL, &[src, id]);

            info!(
                self.log,
                "Voluntary exit";
                "epoch" => %epoch,
                "validator" => %id,
                "src" => src,
            );

            validator.with_epoch_summary(epoch, |summary| summary.register_exit());
        }
    }

    /// Register a proposer slashing from the gossip network.
    pub fn register_gossip_proposer_slashing(&self, slashing: &ProposerSlashing) {
        self.register_proposer_slashing("gossip", slashing)
    }

    /// Register a proposer slashing from the HTTP API.
    pub fn register_api_proposer_slashing(&self, slashing: &ProposerSlashing) {
        self.register_proposer_slashing("api", slashing)
    }

    /// Register a proposer slashing included in a *valid* `BeaconBlock`.
    pub fn register_block_proposer_slashing(&self, slashing: &ProposerSlashing) {
        self.register_proposer_slashing("block", slashing)
    }

    fn register_proposer_slashing(&self, src: &str, slashing: &ProposerSlashing) {
        let proposer = slashing.signed_header_1.message.proposer_index;
        let slot = slashing.signed_header_1.message.slot;
        let epoch = slot.epoch(T::slots_per_epoch());
        let root_1 = slashing.signed_header_1.message.canonical_root();
        let root_2 = slashing.signed_header_2.message.canonical_root();

        if let Some(validator) = self.get_validator(proposer) {
            let id = &validator.id;

            metrics::inc_counter_vec(
                &metrics::VALIDATOR_MONITOR_PROPOSER_SLASHING_TOTAL,
                &[src, id],
            );

            crit!(
                self.log,
                "Proposer slashing";
                "root_2" => %root_2,
                "root_1" => %root_1,
                "slot" => %slot,
                "validator" => %id,
                "src" => src,
            );

            validator.with_epoch_summary(epoch, |summary| summary.register_proposer_slashing());
        }
    }

    /// Register an attester slashing from the gossip network.
    pub fn register_gossip_attester_slashing(&self, slashing: &AttesterSlashing<T>) {
        self.register_attester_slashing("gossip", slashing)
    }

    /// Register an attester slashing from the HTTP API.
    pub fn register_api_attester_slashing(&self, slashing: &AttesterSlashing<T>) {
        self.register_attester_slashing("api", slashing)
    }

    /// Register an attester slashing included in a *valid* `BeaconBlock`.
    pub fn register_block_attester_slashing(&self, slashing: &AttesterSlashing<T>) {
        self.register_attester_slashing("block", slashing)
    }

    fn register_attester_slashing(&self, src: &str, slashing: &AttesterSlashing<T>) {
        let data = &slashing.attestation_1.data;
        let attestation_1_indices: HashSet<u64> = slashing
            .attestation_1
            .attesting_indices
            .iter()
            .copied()
            .collect();

        slashing
            .attestation_2
            .attesting_indices
            .iter()
            .filter(|index| attestation_1_indices.contains(index))
            .filter_map(|index| self.get_validator(*index))
            .for_each(|validator| {
                let id = &validator.id;
                let epoch = data.slot.epoch(T::slots_per_epoch());

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_ATTESTER_SLASHING_TOTAL,
                    &[src, id],
                );

                crit!(
                    self.log,
                    "Attester slashing";
                    "epoch" => %epoch,
                    "slot" => %data.slot,
                    "validator" => %id,
                    "src" => src,
                );

                validator.with_epoch_summary(epoch, |summary| summary.register_attester_slashing());
            })
    }

    /// Scrape `self` for metrics.
    ///
    /// Should be called whenever Prometheus is scraping Lighthouse.
    pub fn scrape_metrics<S: SlotClock>(&self, slot_clock: &S, spec: &ChainSpec) {
        metrics::set_gauge(
            &metrics::VALIDATOR_MONITOR_VALIDATORS_TOTAL,
            self.num_validators() as i64,
        );

        if let Some(slot) = slot_clock.now() {
            let epoch = slot.epoch(T::slots_per_epoch());
            let slot_in_epoch = slot % T::slots_per_epoch();

            // Only start to report on the current epoch once we've progressed past the point where
            // all attestation should be included in a block.
            //
            // This allows us to set alarms on Grafana to detect when an attestation has been
            // missed. If we didn't delay beyond the attestation inclusion period then we could
            // expect some occasional false-positives on attestation misses.
            //
            // I have chosen 3 as an arbitrary number where we *probably* shouldn't see that many
            // skip slots on mainnet.
            let previous_epoch = if slot_in_epoch > spec.min_attestation_inclusion_delay + 3 {
                epoch - 1
            } else {
                epoch - 2
            };

            for (_, validator) in self.validators.iter() {
                let id = &validator.id;
                let summaries = validator.summaries.read();

                if let Some(summary) = summaries.get(&previous_epoch) {
                    /*
                     * Attestations
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATIONS_TOTAL,
                        &[id],
                        summary.attestations as i64,
                    );
                    if let Some(delay) = summary.attestation_min_delay {
                        metrics::observe_timer_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATIONS_MIN_DELAY_SECONDS,
                            &[id],
                            delay,
                        );
                    }
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_AGGREGATE_INCLUSIONS,
                        &[id],
                        summary.attestation_aggregate_incusions as i64,
                    );
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_BLOCK_INCLUSIONS,
                        &[id],
                        summary.attestation_block_inclusions as i64,
                    );
                    if let Some(distance) = summary.attestation_min_block_inclusion_distance {
                        metrics::set_gauge_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_BLOCK_MIN_INCLUSION_DISTANCE,
                            &[id],
                            distance.as_u64() as i64,
                        );
                    }
                    /*
                     * Blocks
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_BEACON_BLOCKS_TOTAL,
                        &[id],
                        summary.blocks as i64,
                    );
                    if let Some(delay) = summary.block_min_delay {
                        metrics::observe_timer_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_BEACON_BLOCKS_MIN_DELAY_SECONDS,
                            &[id],
                            delay,
                        );
                    }
                    /*
                     * Aggregates
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_AGGREGATES_TOTAL,
                        &[id],
                        summary.aggregates as i64,
                    );
                    if let Some(delay) = summary.aggregate_min_delay {
                        metrics::observe_timer_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_AGGREGATES_MIN_DELAY_SECONDS,
                            &[id],
                            delay,
                        );
                    }
                    /*
                     * Other
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_EXITS_TOTAL,
                        &[id],
                        summary.exits as i64,
                    );
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_PROPOSER_SLASHINGS_TOTAL,
                        &[id],
                        summary.proposer_slashings as i64,
                    );
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ATTESTER_SLASHINGS_TOTAL,
                        &[id],
                        summary.attester_slashings as i64,
                    );
                }
            }
        }
    }
}

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}

fn u64_to_i64(n: impl Into<u64>) -> i64 {
    i64::try_from(n.into()).unwrap_or(i64::max_value())
}

/// Returns the delay between the start of `block.slot` and `seen_timestamp`.
pub fn get_block_delay_ms<T: EthSpec, S: SlotClock>(
    seen_timestamp: Duration,
    block: BeaconBlockRef<'_, T>,
    slot_clock: &S,
) -> Duration {
    get_slot_delay_ms::<S>(seen_timestamp, block.slot(), slot_clock)
}

/// Returns the delay between the start of `slot` and `seen_timestamp`.
pub fn get_slot_delay_ms<S: SlotClock>(
    seen_timestamp: Duration,
    slot: Slot,
    slot_clock: &S,
) -> Duration {
    slot_clock
        .start_of(slot)
        .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
        .unwrap_or_else(|| Duration::from_secs(0))
}
