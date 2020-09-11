use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{Epoch, EthSpec, IndexedAttestation};

pub const DEFAULT_CHUNK_SIZE: usize = 16;
pub const DEFAULT_VALIDATOR_CHUNK_SIZE: usize = 256;
pub const DEFAULT_HISTORY_LENGTH: usize = 54_000;
pub const DEFAULT_UPDATE_PERIOD: u64 = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_path: PathBuf,
    pub chunk_size: usize,
    pub validator_chunk_size: usize,
    /// Number of epochs of history to keep.
    pub history_length: usize,
    /// Update frequency in seconds.
    pub update_period: u64,
}

impl Config {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            chunk_size: DEFAULT_CHUNK_SIZE,
            validator_chunk_size: DEFAULT_VALIDATOR_CHUNK_SIZE,
            history_length: DEFAULT_HISTORY_LENGTH,
            update_period: DEFAULT_UPDATE_PERIOD,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.history_length % self.chunk_size != 0 {
            Err(Error::ConfigInvalidChunkSize {
                chunk_size: self.chunk_size,
                history_length: self.history_length,
            })
        } else {
            Ok(())
        }
    }

    pub fn chunk_index(&self, epoch: Epoch) -> usize {
        (epoch.as_usize() % self.history_length) / self.chunk_size
    }

    pub fn validator_chunk_index(&self, validator_index: u64) -> usize {
        validator_index as usize / self.validator_chunk_size
    }

    pub fn chunk_offset(&self, epoch: Epoch) -> usize {
        epoch.as_usize() % self.chunk_size
    }

    pub fn validator_offset(&self, validator_index: u64) -> usize {
        validator_index as usize % self.validator_chunk_size
    }

    /// Map the validator and epoch chunk indexes into a single value for use as a database key.
    pub fn disk_key(&self, validator_chunk_index: usize, chunk_index: usize) -> usize {
        let width = self.history_length / self.chunk_size;
        validator_chunk_index * width + chunk_index
    }

    /// Map the validator and epoch offsets into an index for `Chunk::data`.
    pub fn cell_index(&self, validator_offset: usize, chunk_offset: usize) -> usize {
        validator_offset * self.chunk_size + chunk_offset
    }

    /// Iterate over the attesting indices which belong to the `validator_chunk_index` chunk.
    pub fn attesting_validators_for_chunk<'a, E: EthSpec>(
        &'a self,
        attestation: &'a IndexedAttestation<E>,
        validator_chunk_index: usize,
    ) -> impl Iterator<Item = u64> + 'a {
        attestation
            .attesting_indices
            .iter()
            .filter(move |v| self.validator_chunk_index(**v) == validator_chunk_index)
            .copied()
    }
}
