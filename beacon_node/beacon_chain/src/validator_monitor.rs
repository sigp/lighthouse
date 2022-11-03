//! Provides detailed logging and metrics for a set of registered validators.
//!
//! This component should not affect consensus.

use crate::metrics;
use parking_lot::RwLock;
use slog::{crit, debug, error, info, warn, Logger};
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
    AttesterSlashing, BeaconBlockRef, BeaconState, ChainSpec, Epoch, EthSpec, Hash256,
    IndexedAttestation, ProposerSlashing, PublicKeyBytes, SignedAggregateAndProof,
    SignedContributionAndProof, Slot, SyncCommitteeMessage, VoluntaryExit,
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
    pub attestation_aggregate_inclusions: usize,
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
     * SyncCommitteeMessages in the current epoch
     */
    /// The number of sync committee messages seen.
    sync_committee_messages: usize,
    /// The delay between when the sync committee message should have been produced and when it was observed.
    sync_committee_message_min_delay: Option<Duration>,
    /// The number of times a validator's sync signature was included in the sync aggregate.
    sync_signature_block_inclusions: usize,
    /// The number of times a validator's sync signature was aggregated into a sync contribution.
    sync_signature_contribution_inclusions: usize,

    /*
     * SyncContributions in the current epoch
     */
    /// The number of SyncContributions observed in the current epoch.
    sync_contributions: usize,
    /// The delay between when the sync committee contribution should have been produced and when it was observed.
    sync_contribution_min_delay: Option<Duration>,

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

    pub fn register_sync_committee_message(&mut self, delay: Duration) {
        self.sync_committee_messages += 1;
        Self::update_if_lt(&mut self.sync_committee_message_min_delay, delay);
    }

    pub fn register_aggregated_attestation(&mut self, delay: Duration) {
        self.aggregates += 1;
        Self::update_if_lt(&mut self.aggregate_min_delay, delay);
    }

    pub fn register_sync_committee_contribution(&mut self, delay: Duration) {
        self.sync_contributions += 1;
        Self::update_if_lt(&mut self.sync_contribution_min_delay, delay);
    }

    pub fn register_aggregate_attestation_inclusion(&mut self) {
        self.attestation_aggregate_inclusions += 1;
    }

    pub fn register_sync_signature_contribution_inclusion(&mut self) {
        self.sync_signature_contribution_inclusions += 1;
    }

    pub fn register_attestation_block_inclusion(&mut self, inclusion_distance: Slot) {
        self.attestation_block_inclusions += 1;
        Self::update_if_lt(
            &mut self.attestation_min_block_inclusion_distance,
            inclusion_distance,
        );
    }

    pub fn register_sync_signature_block_inclusions(&mut self) {
        self.sync_signature_block_inclusions += 1;
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

    /// Returns minimum inclusion distance for the given epoch as recorded by the validator monitor.
    ///
    /// Note: this value may be different from the one obtained from epoch summary
    /// as the value recorded by the validator monitor ignores skip slots.
    fn min_inclusion_distance(&self, epoch: &Epoch) -> Option<u64> {
        let summaries = self.summaries.read();
        summaries.get(epoch).and_then(|summary| {
            summary
                .attestation_min_block_inclusion_distance
                .map(Into::into)
        })
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

    /// Ensure epoch summary is added to the summaries map
    fn touch_epoch_summary(&self, epoch: Epoch) {
        self.with_epoch_summary(epoch, |_| {});
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
                monitored_validator.touch_epoch_summary(current_epoch);
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
                        i64::from(validator.slashed),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_ACTIVE,
                        &[id],
                        i64::from(validator.is_active_at(current_epoch)),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_EXITED,
                        &[id],
                        i64::from(validator.is_exited_at(current_epoch)),
                    );
                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_WITHDRAWABLE,
                        &[id],
                        i64::from(validator.is_withdrawable_at(current_epoch)),
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
        summary: &EpochProcessingSummary<T>,
        spec: &ChainSpec,
    ) -> Result<(), EpochProcessingError> {
        let mut attestation_success = Vec::new();
        let mut attestation_miss = Vec::new();
        let mut head_miss = Vec::new();
        let mut target_miss = Vec::new();
        let mut suboptimal_inclusion = Vec::new();

        // We subtract two from the state of the epoch that generated these summaries.
        //
        // - One to account for it being the previous epoch.
        // - One to account for the state advancing an epoch whilst generating the validator
        //     statuses.
        let prev_epoch = epoch - 2;
        for (pubkey, monitored_validator) in self.validators.iter() {
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
                    attestation_success.push(id);
                    debug!(
                        self.log,
                        "Previous epoch attestation success";
                        "matched_source" => previous_epoch_matched_source,
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
                    attestation_miss.push(id);
                    debug!(
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
                    head_miss.push(id);
                    debug!(
                        self.log,
                        "Attestation failed to match head";
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
                    target_miss.push(id);
                    debug!(
                        self.log,
                        "Attestation failed to match target";
                        "epoch" => prev_epoch,
                        "validator" => id,
                    );
                }

                // Get the minimum value among the validator monitor observed inclusion distance
                // and the epoch summary inclusion distance.
                // The inclusion data is not retained in the epoch summary post Altair.
                let min_inclusion_distance = min_opt(
                    monitored_validator.min_inclusion_distance(&prev_epoch),
                    summary
                        .previous_epoch_inclusion_info(i)
                        .map(|info| info.delay),
                );
                if let Some(inclusion_delay) = min_inclusion_distance {
                    if inclusion_delay > spec.min_attestation_inclusion_delay {
                        suboptimal_inclusion.push(id);
                        debug!(
                            self.log,
                            "Potential sub-optimal inclusion delay";
                            "optimal" => spec.min_attestation_inclusion_delay,
                            "delay" => inclusion_delay,
                            "epoch" => prev_epoch,
                            "validator" => id,
                        );
                    }

                    metrics::set_int_gauge(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_INCLUSION_DISTANCE,
                        &[id],
                        inclusion_delay as i64,
                    );
                }

                // Indicates the number of sync committee signatures that made it into
                // a sync aggregate in the current_epoch (state.epoch - 1).
                // Note: Unlike attestations, sync committee signatures must be included in the
                // immediate next slot. Hence, num included sync aggregates for `state.epoch - 1`
                // is available right after state transition to state.epoch.
                let current_epoch = epoch - 1;
                if let Some(sync_committee) = summary.sync_committee() {
                    if sync_committee.contains(pubkey) {
                        metrics::set_int_gauge(
                            &metrics::VALIDATOR_MONITOR_VALIDATOR_IN_CURRENT_SYNC_COMMITTEE,
                            &[id],
                            1,
                        );
                        let epoch_summary = monitored_validator.summaries.read();
                        if let Some(summary) = epoch_summary.get(&current_epoch) {
                            info!(
                                self.log,
                                "Current epoch sync signatures";
                                "included" => summary.sync_signature_block_inclusions,
                                "expected" => T::slots_per_epoch(),
                                "epoch" => current_epoch,
                                "validator" => id,
                            );
                        }
                    } else {
                        metrics::set_int_gauge(
                            &metrics::VALIDATOR_MONITOR_VALIDATOR_IN_CURRENT_SYNC_COMMITTEE,
                            &[id],
                            0,
                        );
                        debug!(
                            self.log,
                            "Validator isn't part of the current sync committee";
                            "epoch" => current_epoch,
                            "validator" => id,
                        );
                    }
                }
            }
        }

        // Aggregate logging for attestation success/failures over an epoch
        // for all validators managed by the validator monitor.
        if !attestation_success.is_empty() {
            info!(
                self.log,
                "Previous epoch attestation(s) success";
                "epoch" => prev_epoch,
                "validators" => ?attestation_success,
            );
        }
        if !attestation_miss.is_empty() {
            error!(
                self.log,
                "Previous epoch attestation(s) missing";
                "epoch" => prev_epoch,
                "validators" => ?attestation_miss,
            );
        }

        if !head_miss.is_empty() {
            warn!(
                self.log,
                "Previous epoch attestation(s) failed to match head";
                "epoch" => prev_epoch,
                "validators" => ?head_miss,
            );
        }

        if !target_miss.is_empty() {
            warn!(
                self.log,
                "Previous epoch attestation(s) failed to match target";
                "epoch" => prev_epoch,
                "validators" => ?target_miss,
            );
        }

        if !suboptimal_inclusion.is_empty() {
            warn!(
                self.log,
                "Previous epoch attestation(s) had sub-optimal inclusion delay";
                "epoch" => prev_epoch,
                "validators" => ?suboptimal_inclusion,
            );
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
        let delay = get_message_delay_ms(
            seen_timestamp,
            data.slot,
            slot_clock.unagg_attestation_production_delay(),
            slot_clock,
        );

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
        let delay = get_message_delay_ms(
            seen_timestamp,
            data.slot,
            slot_clock.agg_attestation_production_delay(),
            slot_clock,
        );

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
    /// `parent_slot` is the slot corresponding to the parent of the beacon block in which
    /// the attestation was included.
    /// We use the parent slot instead of block slot to ignore skip slots when calculating inclusion distance.
    ///
    /// Note: Blocks that get orphaned will skew the inclusion distance calculation.
    pub fn register_attestation_in_block(
        &self,
        indexed_attestation: &IndexedAttestation<T>,
        parent_slot: Slot,
        spec: &ChainSpec,
    ) {
        let data = &indexed_attestation.data;
        // Best effort inclusion distance which ignores skip slots between the parent
        // and the current block. Skipped slots between the attestation slot and the parent
        // slot are still counted for simplicity's sake.
        let inclusion_distance = parent_slot.saturating_sub(data.slot) + 1;

        let delay = inclusion_distance - spec.min_attestation_inclusion_delay;
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
                    summary.register_attestation_block_inclusion(inclusion_distance)
                });
            }
        })
    }

    /// Register a sync committee message received over gossip.
    pub fn register_gossip_sync_committee_message<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        sync_committee_message: &SyncCommitteeMessage,
        slot_clock: &S,
    ) {
        self.register_sync_committee_message(
            "gossip",
            seen_timestamp,
            sync_committee_message,
            slot_clock,
        )
    }

    /// Register a sync committee message received over the http api.
    pub fn register_api_sync_committee_message<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        sync_committee_message: &SyncCommitteeMessage,
        slot_clock: &S,
    ) {
        self.register_sync_committee_message(
            "api",
            seen_timestamp,
            sync_committee_message,
            slot_clock,
        )
    }

    /// Register a sync committee message.
    fn register_sync_committee_message<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        sync_committee_message: &SyncCommitteeMessage,
        slot_clock: &S,
    ) {
        if let Some(validator) = self.get_validator(sync_committee_message.validator_index) {
            let id = &validator.id;

            let epoch = sync_committee_message.slot.epoch(T::slots_per_epoch());
            let delay = get_message_delay_ms(
                seen_timestamp,
                sync_committee_message.slot,
                slot_clock.sync_committee_message_production_delay(),
                slot_clock,
            );

            metrics::inc_counter_vec(
                &metrics::VALIDATOR_MONITOR_SYNC_COMMITTEE_MESSAGES_TOTAL,
                &[src, id],
            );
            metrics::observe_timer_vec(
                &metrics::VALIDATOR_MONITOR_SYNC_COMMITTEE_MESSAGES_DELAY_SECONDS,
                &[src, id],
                delay,
            );

            info!(
                self.log,
                "Sync committee message";
                "head" => %sync_committee_message.beacon_block_root,
                "delay_ms" => %delay.as_millis(),
                "epoch" => %epoch,
                "slot" => %sync_committee_message.slot,
                "src" => src,
                "validator" => %id,
            );

            validator.with_epoch_summary(epoch, |summary| {
                summary.register_sync_committee_message(delay)
            });
        }
    }

    /// Register a sync committee contribution received over gossip.
    pub fn register_gossip_sync_committee_contribution<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        sync_contribution: &SignedContributionAndProof<T>,
        participant_pubkeys: &[PublicKeyBytes],
        slot_clock: &S,
    ) {
        self.register_sync_committee_contribution(
            "gossip",
            seen_timestamp,
            sync_contribution,
            participant_pubkeys,
            slot_clock,
        )
    }

    /// Register a sync committee contribution received over the http api.
    pub fn register_api_sync_committee_contribution<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        sync_contribution: &SignedContributionAndProof<T>,
        participant_pubkeys: &[PublicKeyBytes],
        slot_clock: &S,
    ) {
        self.register_sync_committee_contribution(
            "api",
            seen_timestamp,
            sync_contribution,
            participant_pubkeys,
            slot_clock,
        )
    }

    /// Register a sync committee contribution.
    fn register_sync_committee_contribution<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        sync_contribution: &SignedContributionAndProof<T>,
        participant_pubkeys: &[PublicKeyBytes],
        slot_clock: &S,
    ) {
        let slot = sync_contribution.message.contribution.slot;
        let epoch = slot.epoch(T::slots_per_epoch());
        let beacon_block_root = sync_contribution.message.contribution.beacon_block_root;
        let delay = get_message_delay_ms(
            seen_timestamp,
            slot,
            slot_clock.sync_committee_contribution_production_delay(),
            slot_clock,
        );

        let aggregator_index = sync_contribution.message.aggregator_index;
        if let Some(validator) = self.get_validator(aggregator_index) {
            let id = &validator.id;

            metrics::inc_counter_vec(
                &metrics::VALIDATOR_MONITOR_SYNC_CONTRIBUTIONS_TOTAL,
                &[src, id],
            );
            metrics::observe_timer_vec(
                &metrics::VALIDATOR_MONITOR_SYNC_CONTRIBUTIONS_DELAY_SECONDS,
                &[src, id],
                delay,
            );

            info!(
                self.log,
                "Sync contribution";
                "head" => %beacon_block_root,
                "delay_ms" => %delay.as_millis(),
                "epoch" => %epoch,
                "slot" => %slot,
                "src" => src,
                "validator" => %id,
            );

            validator.with_epoch_summary(epoch, |summary| {
                summary.register_sync_committee_contribution(delay)
            });
        }

        for validator_pubkey in participant_pubkeys.iter() {
            if let Some(validator) = self.validators.get(validator_pubkey) {
                let id = &validator.id;

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_SYNC_COMMITTEE_MESSAGE_IN_CONTRIBUTION_TOTAL,
                    &[src, id],
                );

                info!(
                    self.log,
                    "Sync signature included in contribution";
                    "head" => %beacon_block_root,
                    "delay_ms" => %delay.as_millis(),
                    "epoch" => %epoch,
                    "slot" => %slot,
                    "src" => src,
                    "validator" => %id,
                );

                validator.with_epoch_summary(epoch, |summary| {
                    summary.register_sync_signature_contribution_inclusion()
                });
            }
        }
    }

    /// Register that the `sync_aggregate` was included in a *valid* `BeaconBlock`.
    pub fn register_sync_aggregate_in_block(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        participant_pubkeys: Vec<&PublicKeyBytes>,
    ) {
        let epoch = slot.epoch(T::slots_per_epoch());

        for validator_pubkey in participant_pubkeys {
            if let Some(validator) = self.validators.get(validator_pubkey) {
                let id = &validator.id;

                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_SYNC_COMMITTEE_MESSAGE_IN_BLOCK_TOTAL,
                    &["block", id],
                );

                info!(
                    self.log,
                    "Sync signature included in block";
                    "head" => %beacon_block_root,
                    "epoch" => %epoch,
                    "slot" => %slot,
                    "validator" => %id,
                );

                validator.with_epoch_summary(epoch, |summary| {
                    summary.register_sync_signature_block_inclusions();
                });
            }
        }
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
                        summary.attestation_aggregate_inclusions as i64,
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
                     * Sync committee messages
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_COMMITTEE_MESSAGES_TOTAL,
                        &[id],
                        summary.sync_committee_messages as i64,
                    );
                    if let Some(delay) = summary.sync_committee_message_min_delay {
                        metrics::observe_timer_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_COMMITTEE_MESSAGES_MIN_DELAY_SECONDS,
                            &[id],
                            delay,
                        );
                    }
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_CONTRIBUTION_INCLUSIONS,
                        &[id],
                        summary.sync_signature_contribution_inclusions as i64,
                    );
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_SIGNATURE_BLOCK_INCLUSIONS,
                        &[id],
                        summary.sync_signature_block_inclusions as i64,
                    );

                    /*
                     * Sync contributions
                     */
                    metrics::set_gauge_vec(
                        &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_CONTRIBUTIONS_TOTAL,
                        &[id],
                        summary.sync_contributions as i64,
                    );
                    if let Some(delay) = summary.sync_contribution_min_delay {
                        metrics::observe_timer_vec(
                            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_SYNC_CONTRIBUTION_MIN_DELAY_SECONDS,
                            &[id],
                            delay,
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

/// Returns the duration between when any message could be produced and the `seen_timestamp`.
///
/// `message_production_delay` is the duration from the beginning of the slot when the message
/// should be produced.
/// e.g. for unagg attestations, `message_production_delay = slot_duration / 3`.
///
/// `slot` is the slot for which the message was produced.
fn get_message_delay_ms<S: SlotClock>(
    seen_timestamp: Duration,
    slot: Slot,
    message_production_delay: Duration,
    slot_clock: &S,
) -> Duration {
    slot_clock
        .start_of(slot)
        .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
        .and_then(|gross_delay| gross_delay.checked_sub(message_production_delay))
        .unwrap_or_else(|| Duration::from_secs(0))
}

/// Returns minimum value from the two options if both are `Some` or the
/// value contained if only one of them is Some. Returns `None` if both options are `None`
fn min_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(std::cmp::min(x, y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        _ => None,
    }
}
