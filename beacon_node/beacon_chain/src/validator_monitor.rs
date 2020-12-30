use slog::{debug, info, Logger};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::str::{from_utf8, FromStr, Utf8Error};
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    BeaconBlockHeader, BeaconState, EthSpec, IndexedAttestation, PublicKey, SignedAggregateAndProof,
};

#[derive(Debug)]
pub enum Error {
    InvalidPubkey(String),
    FileError(io::Error),
    InvalidUtf8(Utf8Error),
}

pub struct ValidatorEvent<T: EthSpec> {
    pub timestamp: u64,
    pub location: EventLocation,
    pub data: EventData<T>,
}

#[derive(Copy, Clone, Debug)]
pub enum EventLocation {
    BeaconChain,
    Gossip,
    API,
    Block,
}

pub enum EventData<T: EthSpec> {
    Attestation(IndexedAttestation<T>),
    Block(BeaconBlockHeader),
    Aggregate(SignedAggregateAndProof<T>),
}

struct MonitoredValidator<T: EthSpec> {
    pub id: String,
    pub pubkey: PublicKey,
    pub index: Option<u64>,
    pub events: Vec<ValidatorEvent<T>>,
}

impl<T: EthSpec> MonitoredValidator<T> {
    fn new(pubkey: PublicKey, index: Option<u64>) -> Self {
        Self {
            id: pubkey.to_string(),
            pubkey,
            index,
            events: vec![],
        }
    }
}

pub struct ValidatorMonitor<T: EthSpec> {
    validators: HashMap<PublicKey, MonitoredValidator<T>>,
    indices: HashMap<u64, PublicKey>,
    log: Logger,
}

impl<T: EthSpec> ValidatorMonitor<T> {
    pub fn new(log: Logger) -> Self {
        Self {
            validators: <_>::default(),
            indices: <_>::default(),
            log,
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
            .map(PublicKey::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidPubkey)
            .map(|pubkeys| self.add_validator_pubkeys(pubkeys))
    }

    pub fn add_validator_pubkeys(&mut self, pubkeys: Vec<PublicKey>) {
        for pubkey in pubkeys {
            let index_opt = self
                .indices
                .iter()
                .find(|(_, candidate)| **candidate == pubkey)
                .map(|(index, _)| *index);

            self.validators
                .entry(pubkey.clone())
                .or_insert_with(|| MonitoredValidator::new(pubkey, index_opt));
        }
    }

    pub fn update_validator_indices(&mut self, state: &BeaconState<T>) {
        state
            .validators
            .iter()
            .enumerate()
            .skip(self.indices.len())
            .for_each(|(i, validator)| {
                let i = i as u64;
                if let Ok(pubkey) = validator.pubkey.decompress() {
                    if let Some(validator) = self.validators.get_mut(&pubkey) {
                        validator.index = Some(i);
                    }
                    self.indices.insert(i, pubkey);
                }
            })
    }

    fn get_mut_by_index<'a>(&'a mut self, index: u64) -> Option<&'a mut MonitoredValidator<T>> {
        let pubkey = self.indices.get(&index)?;
        self.validators.get_mut(pubkey)
    }

    pub fn register_api_attestation(&mut self, indexed_attestation: &IndexedAttestation<T>) {
        self.register_attestation(EventLocation::API, indexed_attestation)
    }

    pub fn register_gossip_attestation(&mut self, indexed_attestation: &IndexedAttestation<T>) {
        self.register_attestation(EventLocation::Gossip, indexed_attestation)
    }

    pub fn register_attestation(
        &mut self,
        location: EventLocation,
        indexed_attestation: &IndexedAttestation<T>,
    ) {
        indexed_attestation
            .attesting_indices
            .iter()
            .for_each(|index| {
                let log = self.log.clone();
                if let Some(validator) = self.get_mut_by_index(*index) {
                    info!(
                        log,
                        "Monitored validator attestation";
                        "index" => %indexed_attestation.data.index,
                        "slot" => %indexed_attestation.data.slot,
                        "index" => %indexed_attestation.data.slot,
                        "head" => %indexed_attestation.data.beacon_block_root,
                        "src" => ?location,
                        "validator" => %index,
                    );

                    validator.events.push(ValidatorEvent {
                        timestamp: timestamp_now(),
                        location,
                        data: EventData::Attestation(indexed_attestation.clone()),
                    });
                }
            });
    }
}

fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
