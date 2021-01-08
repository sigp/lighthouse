use crate::metrics;
use parking_lot::RwLock;
use slog::{crit, info, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;
use std::str::{from_utf8, FromStr, Utf8Error};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::{
    AttestationData, AttesterSlashing, BeaconBlock, BeaconState, ChainSpec, Epoch, EthSpec,
    Hash256, IndexedAttestation, ProposerSlashing, PublicKeyBytes, SignedAggregateAndProof, Slot,
    VoluntaryExit,
};

const HISTORIC_EPOCHS: usize = 4;

#[derive(Debug)]
pub enum Error {
    InvalidPubkey(String),
    FileError(io::Error),
    InvalidUtf8(Utf8Error),
}

#[derive(Default)]
struct EpochSummary {
    /*
     * Attestations
     */
    pub attestations: usize,
    pub attestation_min_delay: Option<Duration>,
    pub attestation_aggregate_incusions: usize,
    pub attestation_block_inclusions: usize,
    pub attestation_min_block_inclusion_distance: Option<Slot>,
    /*
     * Blocks
     */
    pub blocks: usize,
    pub block_min_delay: Option<Duration>,
    /*
     * Aggregates
     */
    pub aggregates: usize,
    pub aggregate_min_delay: Option<Duration>,
    /*
     * Others
     */
    pub exits: usize,
    pub proposer_slashings: usize,
    pub attester_slashings: usize,
}

impl EpochSummary {
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

struct MonitoredValidator {
    pub id: String,
    pub pubkey: PublicKeyBytes,
    pub index: Option<u64>,
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

    fn with_epoch_summary<F>(&self, epoch: Epoch, func: F)
    where
        F: Fn(&mut EpochSummary),
    {
        let mut summaries = self.summaries.write();

        func(
            summaries
                .entry(epoch)
                .or_insert_with(|| EpochSummary::default()),
        );

        // Prune
        while summaries.len() > HISTORIC_EPOCHS {
            if let Some(key) = summaries.iter().map(|(epoch, _)| *epoch).min() {
                summaries.remove(&key);
            }
        }
    }
}

pub struct ValidatorMonitor<T> {
    validators: HashMap<PublicKeyBytes, MonitoredValidator>,
    indices: HashMap<u64, PublicKeyBytes>,
    auto_register: bool,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> ValidatorMonitor<T> {
    pub fn new(auto_register: bool, log: Logger) -> Self {
        Self {
            validators: <_>::default(),
            indices: <_>::default(),
            auto_register,
            log,
            _phantom: PhantomData,
        }
    }

    pub fn add_validators_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let mut bytes = vec![];
        OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(Error::FileError)?;

        self.add_validators_from_comma_separated_str(from_utf8(&bytes).map_err(Error::InvalidUtf8)?)
    }

    pub fn add_validators_from_comma_separated_str(
        &mut self,
        validator_pubkeys: &str,
    ) -> Result<(), Error> {
        validator_pubkeys
            .split(",")
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidPubkey)
            .map(|pubkeys| self.add_validator_pubkeys(pubkeys))
    }

    pub fn add_validator_pubkeys(&mut self, pubkeys: Vec<PublicKeyBytes>) {
        for pubkey in pubkeys {
            self.add_validator_pubkey(pubkey)
        }
    }

    pub fn add_validator_pubkey(&mut self, pubkey: PublicKeyBytes) {
        let index_opt = self
            .indices
            .iter()
            .find(|(_, candidate_pk)| **candidate_pk == pubkey)
            .map(|(index, _)| *index);

        self.validators
            .entry(pubkey)
            .or_insert_with(|| MonitoredValidator::new(pubkey, index_opt));
    }

    pub fn update_validator_indices(&mut self, state: &BeaconState<T>) {
        state
            .validators
            .iter()
            .enumerate()
            .skip(self.indices.len())
            .for_each(|(i, validator)| {
                let i = i as u64;
                if let Some(validator) = self.validators.get_mut(&validator.pubkey) {
                    validator.set_index(i)
                }
                self.indices.insert(i, validator.pubkey);
            })
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

    pub fn num_validators(&self) -> usize {
        self.validators.len()
    }

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

    pub fn get_block_delay_ms<S: SlotClock>(
        seen_timestamp: Duration,
        block: &BeaconBlock<T>,
        slot_clock: &S,
    ) -> Duration {
        slot_clock
            .start_of(block.slot)
            .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    pub fn register_gossip_block<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        block: &BeaconBlock<T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        self.register_beacon_block("gossip", seen_timestamp, block, block_root, slot_clock)
    }

    pub fn register_api_block<S: SlotClock>(
        &self,
        seen_timestamp: Duration,
        block: &BeaconBlock<T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        self.register_beacon_block("api", seen_timestamp, block, block_root, slot_clock)
    }

    pub fn register_beacon_block<S: SlotClock>(
        &self,
        src: &str,
        seen_timestamp: Duration,
        block: &BeaconBlock<T>,
        block_root: Hash256,
        slot_clock: &S,
    ) {
        if let Some(id) = self.get_validator_id(block.proposer_index) {
            let delay = Self::get_block_delay_ms(seen_timestamp, block, slot_clock);

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
                "slot" => %block.slot,
                "src" => src,
                "validator" => %id,
            );
        }
    }

    pub fn get_unaggregated_attestation_delay_ms<S: SlotClock>(
        seen_timestamp: Duration,
        data: &AttestationData,
        slot_clock: &S,
    ) -> Duration {
        slot_clock
            .start_of(data.slot)
            .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
            .and_then(|gross_delay| {
                let production_delay = slot_clock.slot_duration() / 3;
                gross_delay.checked_sub(production_delay)
            })
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    pub fn get_aggregated_attestation_delay_ms<S: SlotClock>(
        seen_timestamp: Duration,
        data: &AttestationData,
        slot_clock: &S,
    ) -> Duration {
        slot_clock
            .start_of(data.slot)
            .and_then(|slot_start| seen_timestamp.checked_sub(slot_start))
            .and_then(|gross_delay| {
                let production_delay = slot_clock.slot_duration() / 2;
                gross_delay.checked_sub(production_delay)
            })
            .unwrap_or_else(|| Duration::from_secs(0))
    }

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
    pub fn register_api_aggregated_attestation<S: SlotClock>(
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

    pub fn register_attestation_in_block(
        &self,
        indexed_attestation: &IndexedAttestation<T>,
        block: &BeaconBlock<T>,
        spec: &ChainSpec,
    ) {
        let data = &indexed_attestation.data;
        let delay = (block.slot - data.slot) - spec.min_attestation_inclusion_delay;
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

    pub fn register_gossip_voluntary_exit(&self, seen_timestamp: Duration, exit: &VoluntaryExit) {
        self.register_voluntary_exit("gossip", seen_timestamp, exit)
    }

    pub fn register_api_voluntary_exit(&self, seen_timestamp: Duration, exit: &VoluntaryExit) {
        self.register_voluntary_exit("api", seen_timestamp, exit)
    }

    fn register_voluntary_exit(&self, src: &str, seen_timestamp: Duration, exit: &VoluntaryExit) {
        if let Some(validator) = self.get_validator(exit.validator_index) {
            let id = &validator.id;
            let epoch = exit.epoch;

            metrics::inc_counter_vec(&metrics::VALIDATOR_MONITOR_EXIT_TOTAL, &[src, id]);

            info!(
                self.log,
                "Voluntary exit";
                "seen_timestamp" => %seen_timestamp.as_millis(),
                "epoch" => %epoch,
                "validator" => %id,
                "src" => src,
            );

            validator.with_epoch_summary(epoch, |summary| summary.register_exit());
        }
    }

    pub fn register_gossip_proposer_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &ProposerSlashing,
    ) {
        self.register_proposer_slashing("gossip", seen_timestamp, slashing)
    }

    pub fn register_api_proposer_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &ProposerSlashing,
    ) {
        self.register_proposer_slashing("api", seen_timestamp, slashing)
    }

    pub fn register_block_proposer_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &ProposerSlashing,
    ) {
        self.register_proposer_slashing("block", seen_timestamp, slashing)
    }

    fn register_proposer_slashing(
        &self,
        src: &str,
        seen_timestamp: Duration,
        slashing: &ProposerSlashing,
    ) {
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
                "seen_timestamp" => %seen_timestamp.as_millis(),
                "root_2" => %root_2,
                "root_1" => %root_1,
                "slot" => %slot,
                "validator" => %id,
                "src" => src,
            );

            validator.with_epoch_summary(epoch, |summary| summary.register_proposer_slashing());
        }
    }

    pub fn register_gossip_attester_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &AttesterSlashing<T>,
    ) {
        self.register_attester_slashing("gossip", seen_timestamp, slashing)
    }

    pub fn register_api_attester_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &AttesterSlashing<T>,
    ) {
        self.register_attester_slashing("api", seen_timestamp, slashing)
    }

    pub fn register_block_attester_slashing(
        &self,
        seen_timestamp: Duration,
        slashing: &AttesterSlashing<T>,
    ) {
        self.register_attester_slashing("block", seen_timestamp, slashing)
    }

    fn register_attester_slashing(
        &self,
        src: &str,
        seen_timestamp: Duration,
        slashing: &AttesterSlashing<T>,
    ) {
        let data = &slashing.attestation_1.data;
        let attestation_1_indices: HashSet<u64> =
            HashSet::from_iter(slashing.attestation_1.attesting_indices.iter().copied());

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
                    "seen_timestamp" => %seen_timestamp.as_millis(),
                    "epoch" => %epoch,
                    "slot" => %data.slot,
                    "validator" => %id,
                    "src" => src,
                );

                validator.with_epoch_summary(epoch, |summary| summary.register_attester_slashing());
            })
    }

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

pub fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}
