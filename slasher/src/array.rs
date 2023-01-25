use crate::metrics::{self, SLASHER_COMPRESSION_RATIO, SLASHER_NUM_CHUNKS_UPDATED};
use crate::{
    AttesterSlashingStatus, Config, Database, Error, IndexedAttesterRecord, RwTransaction,
    SlasherDB,
};
use flate2::bufread::{ZlibDecoder, ZlibEncoder};
use serde_derive::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::{btree_map::Entry, BTreeMap, HashSet};
use std::convert::TryFrom;
use std::io::Read;
use std::iter::Extend;
use std::sync::Arc;
use types::{AttesterSlashing, Epoch, EthSpec, IndexedAttestation};

pub const MAX_DISTANCE: u16 = u16::MAX;

/// Terminology:
///
/// Let
///     N = config.history_length
///     C = config.chunk_size
///     K = config.validator_chunk_size
///
/// Then
///
/// `chunk_index` in [0..N/C) is the column of a chunk in the 2D matrix
/// `validator_chunk_index` in [0..N/K) is the row of a chunk in the 2D matrix
/// `chunk_offset` in [0..C) is the horizontal (epoch) offset of a value within a 2D chunk
/// `validator_offset` in [0..K) is the vertical (validator) offset of a value within a 2D chunk
#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    data: Vec<u16>,
}

impl Chunk {
    pub fn get_target(
        &self,
        validator_index: u64,
        epoch: Epoch,
        config: &Config,
    ) -> Result<Epoch, Error> {
        assert_eq!(
            self.data.len(),
            config.chunk_size * config.validator_chunk_size
        );
        let validator_offset = config.validator_offset(validator_index);
        let chunk_offset = config.chunk_offset(epoch);
        let cell_index = config.cell_index(validator_offset, chunk_offset);
        self.data
            .get(cell_index)
            .map(|distance| epoch + u64::from(*distance))
            .ok_or(Error::ChunkIndexOutOfBounds(cell_index))
    }

    pub fn set_target(
        &mut self,
        validator_index: u64,
        epoch: Epoch,
        target_epoch: Epoch,
        config: &Config,
    ) -> Result<(), Error> {
        let distance = Self::epoch_distance(target_epoch, epoch)?;
        self.set_raw_distance(validator_index, epoch, distance, config)
    }

    pub fn set_raw_distance(
        &mut self,
        validator_index: u64,
        epoch: Epoch,
        target_distance: u16,
        config: &Config,
    ) -> Result<(), Error> {
        let validator_offset = config.validator_offset(validator_index);
        let chunk_offset = config.chunk_offset(epoch);
        let cell_index = config.cell_index(validator_offset, chunk_offset);

        let cell = self
            .data
            .get_mut(cell_index)
            .ok_or(Error::ChunkIndexOutOfBounds(cell_index))?;
        *cell = target_distance;
        Ok(())
    }

    /// Compute the distance (difference) between two epochs.
    ///
    /// Error if the distance is greater than or equal to `MAX_DISTANCE`.
    pub fn epoch_distance(epoch: Epoch, base_epoch: Epoch) -> Result<u16, Error> {
        let distance_u64 = epoch
            .as_u64()
            .checked_sub(base_epoch.as_u64())
            .ok_or(Error::DistanceCalculationOverflow)?;

        let distance = u16::try_from(distance_u64).map_err(|_| Error::DistanceTooLarge)?;
        if distance < MAX_DISTANCE {
            Ok(distance)
        } else {
            Err(Error::DistanceTooLarge)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MinTargetChunk {
    chunk: Chunk,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MaxTargetChunk {
    chunk: Chunk,
}

pub trait TargetArrayChunk: Sized + serde::Serialize + serde::de::DeserializeOwned {
    fn name() -> &'static str;

    fn empty(config: &Config) -> Self;

    fn chunk(&mut self) -> &mut Chunk;

    fn neutral_element() -> u16;

    fn check_slashable<E: EthSpec>(
        &self,
        db: &SlasherDB<E>,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        attestation: &IndexedAttestation<E>,
        config: &Config,
    ) -> Result<AttesterSlashingStatus<E>, Error>;

    fn update(
        &mut self,
        chunk_index: usize,
        validator_index: u64,
        start_epoch: Epoch,
        new_target_epoch: Epoch,
        current_epoch: Epoch,
        config: &Config,
    ) -> Result<bool, Error>;

    fn first_start_epoch(
        source_epoch: Epoch,
        current_epoch: Epoch,
        config: &Config,
    ) -> Option<Epoch>;

    fn next_start_epoch(start_epoch: Epoch, config: &Config) -> Epoch;

    fn select_db<E: EthSpec>(db: &SlasherDB<E>) -> &Database;

    fn load<E: EthSpec>(
        db: &SlasherDB<E>,
        txn: &mut RwTransaction<'_>,
        validator_chunk_index: usize,
        chunk_index: usize,
        config: &Config,
    ) -> Result<Option<Self>, Error> {
        let disk_key = config.disk_key(validator_chunk_index, chunk_index);
        let chunk_bytes = match txn.get(Self::select_db(db), &disk_key.to_be_bytes())? {
            Some(chunk_bytes) => chunk_bytes,
            None => return Ok(None),
        };

        let chunk = bincode::deserialize_from(ZlibDecoder::new(chunk_bytes.borrow()))?;

        Ok(Some(chunk))
    }

    fn store<E: EthSpec>(
        &self,
        db: &SlasherDB<E>,
        txn: &mut RwTransaction<'_>,
        validator_chunk_index: usize,
        chunk_index: usize,
        config: &Config,
    ) -> Result<(), Error> {
        let disk_key = config.disk_key(validator_chunk_index, chunk_index);
        let value = bincode::serialize(self)?;
        let mut encoder = ZlibEncoder::new(&value[..], flate2::Compression::default());
        let mut compressed_value = vec![];
        encoder.read_to_end(&mut compressed_value)?;

        let compression_ratio = value.len() as f64 / compressed_value.len() as f64;
        metrics::set_float_gauge(&SLASHER_COMPRESSION_RATIO, compression_ratio);

        txn.put(
            Self::select_db(db),
            disk_key.to_be_bytes(),
            &compressed_value,
        )?;
        Ok(())
    }
}

impl TargetArrayChunk for MinTargetChunk {
    fn name() -> &'static str {
        "min"
    }

    fn empty(config: &Config) -> Self {
        MinTargetChunk {
            chunk: Chunk {
                data: vec![
                    Self::neutral_element();
                    config.chunk_size * config.validator_chunk_size
                ],
            },
        }
    }

    fn neutral_element() -> u16 {
        MAX_DISTANCE
    }

    fn chunk(&mut self) -> &mut Chunk {
        &mut self.chunk
    }

    fn check_slashable<E: EthSpec>(
        &self,
        db: &SlasherDB<E>,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        attestation: &IndexedAttestation<E>,
        config: &Config,
    ) -> Result<AttesterSlashingStatus<E>, Error> {
        let min_target =
            self.chunk
                .get_target(validator_index, attestation.data.source.epoch, config)?;
        if attestation.data.target.epoch > min_target {
            let existing_attestation =
                db.get_attestation_for_validator(txn, validator_index, min_target)?;

            if attestation.data.source.epoch < existing_attestation.data.source.epoch {
                Ok(AttesterSlashingStatus::SurroundsExisting(Box::new(
                    existing_attestation,
                )))
            } else {
                Ok(AttesterSlashingStatus::AlreadyDoubleVoted)
            }
        } else {
            Ok(AttesterSlashingStatus::NotSlashable)
        }
    }

    fn update(
        &mut self,
        chunk_index: usize,
        validator_index: u64,
        start_epoch: Epoch,
        new_target_epoch: Epoch,
        current_epoch: Epoch,
        config: &Config,
    ) -> Result<bool, Error> {
        let min_epoch = Epoch::from(
            current_epoch
                .as_usize()
                .saturating_sub(config.history_length - 1),
        );
        let mut epoch = start_epoch;
        while config.chunk_index(epoch) == chunk_index && epoch >= min_epoch {
            if new_target_epoch < self.chunk.get_target(validator_index, epoch, config)? {
                self.chunk
                    .set_target(validator_index, epoch, new_target_epoch, config)?;
            } else {
                // We can stop.
                return Ok(false);
            }
            epoch -= 1;
        }
        Ok(epoch >= min_epoch)
    }

    fn first_start_epoch(
        source_epoch: Epoch,
        current_epoch: Epoch,
        config: &Config,
    ) -> Option<Epoch> {
        if source_epoch > current_epoch - config.history_length as u64 {
            assert_ne!(source_epoch, 0);
            Some(source_epoch - 1)
        } else {
            None
        }
    }

    // Move to last epoch of previous chunk
    fn next_start_epoch(start_epoch: Epoch, config: &Config) -> Epoch {
        let chunk_size = config.chunk_size as u64;
        start_epoch / chunk_size * chunk_size - 1
    }

    fn select_db<E: EthSpec>(db: &SlasherDB<E>) -> &Database {
        &db.databases.min_targets_db
    }
}

impl TargetArrayChunk for MaxTargetChunk {
    fn name() -> &'static str {
        "max"
    }

    fn empty(config: &Config) -> Self {
        MaxTargetChunk {
            chunk: Chunk {
                data: vec![
                    Self::neutral_element();
                    config.chunk_size * config.validator_chunk_size
                ],
            },
        }
    }

    fn neutral_element() -> u16 {
        0
    }

    fn chunk(&mut self) -> &mut Chunk {
        &mut self.chunk
    }

    fn check_slashable<E: EthSpec>(
        &self,
        db: &SlasherDB<E>,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        attestation: &IndexedAttestation<E>,
        config: &Config,
    ) -> Result<AttesterSlashingStatus<E>, Error> {
        let max_target =
            self.chunk
                .get_target(validator_index, attestation.data.source.epoch, config)?;
        if attestation.data.target.epoch < max_target {
            let existing_attestation =
                db.get_attestation_for_validator(txn, validator_index, max_target)?;

            if existing_attestation.data.source.epoch < attestation.data.source.epoch {
                Ok(AttesterSlashingStatus::SurroundedByExisting(Box::new(
                    existing_attestation,
                )))
            } else {
                Ok(AttesterSlashingStatus::AlreadyDoubleVoted)
            }
        } else {
            Ok(AttesterSlashingStatus::NotSlashable)
        }
    }

    fn update(
        &mut self,
        chunk_index: usize,
        validator_index: u64,
        start_epoch: Epoch,
        new_target_epoch: Epoch,
        current_epoch: Epoch,
        config: &Config,
    ) -> Result<bool, Error> {
        let mut epoch = start_epoch;
        while config.chunk_index(epoch) == chunk_index && epoch <= current_epoch {
            if new_target_epoch > self.chunk.get_target(validator_index, epoch, config)? {
                self.chunk
                    .set_target(validator_index, epoch, new_target_epoch, config)?;
            } else {
                // We can stop.
                return Ok(false);
            }
            epoch += 1;
        }
        // If the epoch to update now lies beyond the current chunk and is less than
        // or equal to the current epoch, then continue to the next chunk to update it.
        Ok(epoch <= current_epoch)
    }

    fn first_start_epoch(
        source_epoch: Epoch,
        current_epoch: Epoch,
        _config: &Config,
    ) -> Option<Epoch> {
        if source_epoch < current_epoch {
            Some(source_epoch + 1)
        } else {
            None
        }
    }

    // Move to first epoch of next chunk
    fn next_start_epoch(start_epoch: Epoch, config: &Config) -> Epoch {
        let chunk_size = config.chunk_size as u64;
        (start_epoch / chunk_size + 1) * chunk_size
    }

    fn select_db<E: EthSpec>(db: &SlasherDB<E>) -> &Database {
        &db.databases.max_targets_db
    }
}

pub fn get_chunk_for_update<'a, E: EthSpec, T: TargetArrayChunk>(
    db: &SlasherDB<E>,
    txn: &mut RwTransaction<'_>,
    updated_chunks: &'a mut BTreeMap<usize, T>,
    validator_chunk_index: usize,
    chunk_index: usize,
    config: &Config,
) -> Result<&'a mut T, Error> {
    Ok(match updated_chunks.entry(chunk_index) {
        Entry::Occupied(occupied) => occupied.into_mut(),
        Entry::Vacant(vacant) => {
            let chunk = if let Some(disk_chunk) =
                T::load(db, txn, validator_chunk_index, chunk_index, config)?
            {
                disk_chunk
            } else {
                T::empty(config)
            };
            vacant.insert(chunk)
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub fn apply_attestation_for_validator<E: EthSpec, T: TargetArrayChunk>(
    db: &SlasherDB<E>,
    txn: &mut RwTransaction<'_>,
    updated_chunks: &mut BTreeMap<usize, T>,
    validator_chunk_index: usize,
    validator_index: u64,
    attestation: &IndexedAttestation<E>,
    current_epoch: Epoch,
    config: &Config,
) -> Result<AttesterSlashingStatus<E>, Error> {
    let mut chunk_index = config.chunk_index(attestation.data.source.epoch);
    let mut current_chunk = get_chunk_for_update(
        db,
        txn,
        updated_chunks,
        validator_chunk_index,
        chunk_index,
        config,
    )?;

    let slashing_status =
        current_chunk.check_slashable(db, txn, validator_index, attestation, config)?;

    if slashing_status != AttesterSlashingStatus::NotSlashable {
        return Ok(slashing_status);
    }

    let mut start_epoch = if let Some(start_epoch) =
        T::first_start_epoch(attestation.data.source.epoch, current_epoch, config)
    {
        start_epoch
    } else {
        return Ok(slashing_status);
    };

    loop {
        chunk_index = config.chunk_index(start_epoch);
        current_chunk = get_chunk_for_update(
            db,
            txn,
            updated_chunks,
            validator_chunk_index,
            chunk_index,
            config,
        )?;
        let keep_going = current_chunk.update(
            chunk_index,
            validator_index,
            start_epoch,
            attestation.data.target.epoch,
            current_epoch,
            config,
        )?;
        if !keep_going {
            break;
        }
        start_epoch = T::next_start_epoch(start_epoch, config);
    }

    Ok(AttesterSlashingStatus::NotSlashable)
}

pub fn update<E: EthSpec>(
    db: &SlasherDB<E>,
    txn: &mut RwTransaction<'_>,
    validator_chunk_index: usize,
    batch: Vec<Arc<IndexedAttesterRecord<E>>>,
    current_epoch: Epoch,
    config: &Config,
) -> Result<HashSet<AttesterSlashing<E>>, Error> {
    // Split the batch up into horizontal segments.
    // Map chunk indexes in the range `0..self.config.chunk_size` to attestations
    // for those chunks.
    let mut chunk_attestations = BTreeMap::new();
    for attestation in batch {
        chunk_attestations
            .entry(config.chunk_index(attestation.indexed.data.source.epoch))
            .or_insert_with(Vec::new)
            .push(attestation);
    }

    let mut slashings = update_array::<_, MinTargetChunk>(
        db,
        txn,
        validator_chunk_index,
        &chunk_attestations,
        current_epoch,
        config,
    )?;
    slashings.extend(update_array::<_, MaxTargetChunk>(
        db,
        txn,
        validator_chunk_index,
        &chunk_attestations,
        current_epoch,
        config,
    )?);

    // Update all current epochs.
    for validator_index in config.validator_indices_in_chunk(validator_chunk_index) {
        db.update_current_epoch_for_validator(validator_index, current_epoch, txn)?;
    }

    Ok(slashings)
}

pub fn epoch_update_for_validator<E: EthSpec, T: TargetArrayChunk>(
    db: &SlasherDB<E>,
    txn: &mut RwTransaction<'_>,
    updated_chunks: &mut BTreeMap<usize, T>,
    validator_chunk_index: usize,
    validator_index: u64,
    current_epoch: Epoch,
    config: &Config,
) -> Result<(), Error> {
    let previous_current_epoch =
        if let Some(epoch) = db.get_current_epoch_for_validator(validator_index, txn)? {
            epoch
        } else {
            return Ok(());
        };

    let mut epoch = previous_current_epoch;

    while epoch <= current_epoch {
        let chunk_index = config.chunk_index(epoch);
        let current_chunk = get_chunk_for_update(
            db,
            txn,
            updated_chunks,
            validator_chunk_index,
            chunk_index,
            config,
        )?;
        while config.chunk_index(epoch) == chunk_index && epoch <= current_epoch {
            current_chunk.chunk().set_raw_distance(
                validator_index,
                epoch,
                T::neutral_element(),
                config,
            )?;
            epoch += 1;
        }
    }

    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn update_array<E: EthSpec, T: TargetArrayChunk>(
    db: &SlasherDB<E>,
    txn: &mut RwTransaction<'_>,
    validator_chunk_index: usize,
    chunk_attestations: &BTreeMap<usize, Vec<Arc<IndexedAttesterRecord<E>>>>,
    current_epoch: Epoch,
    config: &Config,
) -> Result<HashSet<AttesterSlashing<E>>, Error> {
    let mut slashings = HashSet::new();
    // Map from chunk index to updated chunk at that index.
    let mut updated_chunks = BTreeMap::new();

    // Update the arrays for the change of current epoch.
    for validator_index in config.validator_indices_in_chunk(validator_chunk_index) {
        epoch_update_for_validator(
            db,
            txn,
            &mut updated_chunks,
            validator_chunk_index,
            validator_index,
            current_epoch,
            config,
        )?;
    }

    for attestations in chunk_attestations.values() {
        for attestation in attestations {
            for validator_index in
                config.attesting_validators_in_chunk(&attestation.indexed, validator_chunk_index)
            {
                let slashing_status = apply_attestation_for_validator::<E, T>(
                    db,
                    txn,
                    &mut updated_chunks,
                    validator_chunk_index,
                    validator_index,
                    &attestation.indexed,
                    current_epoch,
                    config,
                )?;
                if let Some(slashing) = slashing_status.into_slashing(&attestation.indexed) {
                    slashings.insert(slashing);
                }
            }
        }
    }

    // Store chunks on disk.
    metrics::inc_counter_vec_by(
        &SLASHER_NUM_CHUNKS_UPDATED,
        &[T::name()],
        updated_chunks.len() as u64,
    );

    for (chunk_index, chunk) in updated_chunks {
        chunk.store(db, txn, validator_chunk_index, chunk_index, config)?;
    }

    Ok(slashings)
}
