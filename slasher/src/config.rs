use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{Epoch, EthSpec, IndexedAttestation};

pub const DEFAULT_CHUNK_SIZE: usize = 16;
pub const DEFAULT_VALIDATOR_CHUNK_SIZE: usize = 256;
pub const DEFAULT_HISTORY_LENGTH: usize = 4096;
pub const DEFAULT_UPDATE_PERIOD: u64 = 12;
pub const DEFAULT_MAX_DB_SIZE: usize = 256 * 1024; // 256 GiB
pub const DEFAULT_BROADCAST: bool = false;

/// Database size to use for tests.
///
/// Mostly a workaround for Windows due to a bug in LMDB, see:
///
/// https://github.com/sigp/lighthouse/issues/2342
pub const TESTING_MAX_DB_SIZE: usize = 16; // MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_path: PathBuf,
    pub chunk_size: usize,
    pub validator_chunk_size: usize,
    /// Number of epochs of history to keep.
    pub history_length: usize,
    /// Update frequency in seconds.
    pub update_period: u64,
    /// Maximum size of the LMDB database in megabytes.
    pub max_db_size_mbs: usize,
    /// Whether to broadcast slashings found to the network.
    pub broadcast: bool,
}

impl Config {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            chunk_size: DEFAULT_CHUNK_SIZE,
            validator_chunk_size: DEFAULT_VALIDATOR_CHUNK_SIZE,
            history_length: DEFAULT_HISTORY_LENGTH,
            update_period: DEFAULT_UPDATE_PERIOD,
            max_db_size_mbs: DEFAULT_MAX_DB_SIZE,
            broadcast: DEFAULT_BROADCAST,
        }
    }

    /// Use a smaller max DB size for testing.
    pub fn for_testing(mut self) -> Self {
        self.max_db_size_mbs = TESTING_MAX_DB_SIZE;
        self
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.chunk_size == 0
            || self.validator_chunk_size == 0
            || self.history_length == 0
            || self.max_db_size_mbs == 0
        {
            Err(Error::ConfigInvalidZeroParameter {
                config: self.clone(),
            })
        } else if self.history_length % self.chunk_size != 0 {
            Err(Error::ConfigInvalidChunkSize {
                chunk_size: self.chunk_size,
                history_length: self.history_length,
            })
        } else {
            Ok(())
        }
    }

    pub fn is_compatible(&self, other: &Config) -> bool {
        self.chunk_size == other.chunk_size
            && self.validator_chunk_size == other.validator_chunk_size
            && self.history_length == other.history_length
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

    /// Return an iterator over all the validator indices in a validator chunk.
    pub fn validator_indices_in_chunk(
        &self,
        validator_chunk_index: usize,
    ) -> impl Iterator<Item = u64> {
        (validator_chunk_index * self.validator_chunk_size
            ..(validator_chunk_index + 1) * self.validator_chunk_size)
            .map(|index| index as u64)
    }

    /// Iterate over the attesting indices which belong to the `validator_chunk_index` chunk.
    pub fn attesting_validators_in_chunk<'a, E: EthSpec>(
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
