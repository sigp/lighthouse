use crate::metrics;
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
    AttestationData, AttesterSlashing, BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256,
    IndexedAttestation, ProposerSlashing, PublicKeyBytes, SignedAggregateAndProof, VoluntaryExit,
};

#[derive(Debug)]
pub enum Error {
    InvalidPubkey(String),
    FileError(io::Error),
    InvalidUtf8(Utf8Error),
}

struct MonitoredValidator {
    pub id: String,
    pub pubkey: PublicKeyBytes,
    pub index: Option<u64>,
}

impl MonitoredValidator {
    fn new(pubkey: PublicKeyBytes, index: Option<u64>) -> Self {
        Self {
            id: pubkey.to_string(),
            pubkey,
            index,
        }
    }
}

pub struct ValidatorMonitor<T> {
    validators: HashMap<PublicKeyBytes, MonitoredValidator>,
    indices: HashMap<u64, (PublicKeyBytes, String)>,
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

    pub fn register_local_validator(&mut self, validator_index: u64) {
        if !self.auto_register {
            return;
        }

        if let Some((pubkey, _)) = self.indices.get(&validator_index) {
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

    pub fn add_validator_pubkeys(&mut self, pubkeys: Vec<PublicKeyBytes>) {
        for pubkey in pubkeys {
            self.add_validator_pubkey(pubkey)
        }
    }

    pub fn add_validator_pubkey(&mut self, pubkey: PublicKeyBytes) {
        let index_opt = self
            .indices
            .iter()
            .find(|(_, (candidate_pk, _))| *candidate_pk == pubkey)
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
                    validator.index = Some(i);
                }
                self.indices.insert(i, (validator.pubkey, i.to_string()));
            })
    }

    pub fn get_validator_id(&self, validator_index: u64) -> Option<&str> {
        self.indices
            .get(&validator_index)
            .filter(|(pubkey, _id)| self.validators.contains_key(pubkey))
            .map(|(_pubkey, id)| id.as_str())
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
            if let Some(id) = self.get_validator_id(*i) {
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
        if let Some(id) = self.get_validator_id(aggregator_index) {
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
        }

        indexed_attestation.attesting_indices.iter().for_each(|i| {
            if let Some(id) = self.get_validator_id(*i) {
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
            if let Some(id) = self.get_validator_id(*i) {
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
        if let Some(id) = self.get_validator_id(exit.validator_index) {
            metrics::inc_counter_vec(&metrics::VALIDATOR_MONITOR_EXIT_TOTAL, &[src, id]);

            info!(
                self.log,
                "Voluntary exit";
                "seen_timestamp" => %seen_timestamp.as_millis(),
                "epoch" => %exit.epoch,
                "validator" => %id,
                "src" => src,
            );
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
        let root_1 = slashing.signed_header_1.message.canonical_root();
        let root_2 = slashing.signed_header_2.message.canonical_root();

        if let Some(id) = self.get_validator_id(proposer) {
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
            .filter_map(|index| self.get_validator_id(*index))
            .for_each(|id| {
                metrics::inc_counter_vec(
                    &metrics::VALIDATOR_MONITOR_ATTESTER_SLASHING_TOTAL,
                    &[src, id],
                );

                crit!(
                    self.log,
                    "Attester slashing";
                    "seen_timestamp" => %seen_timestamp.as_millis(),
                    "epoch" => %data.slot.epoch(T::slots_per_epoch()),
                    "slot" => %data.slot,
                    "validator" => %id,
                    "src" => src,
                );
            })
    }
}

pub fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}
