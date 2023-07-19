use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use strum::{Display, EnumString, EnumVariantNames};
use types::{Epoch, EthSpec, IndexedAttestation};

pub const DEFAULT_CHUNK_SIZE: usize = 16;
pub const DEFAULT_VALIDATOR_CHUNK_SIZE: usize = 256;
pub const DEFAULT_HISTORY_LENGTH: usize = 4096;
pub const DEFAULT_UPDATE_PERIOD: u64 = 12;
pub const DEFAULT_SLOT_OFFSET: f64 = 10.5;
pub const DEFAULT_MAX_DB_SIZE: usize = 256 * 1024; // 256 GiB
pub const DEFAULT_ATTESTATION_ROOT_CACHE_SIZE: usize = 100_000;
pub const DEFAULT_BROADCAST: bool = false;

#[cfg(all(feature = "mdbx", not(feature = "lmdb")))]
pub const DEFAULT_BACKEND: DatabaseBackend = DatabaseBackend::Mdbx;
#[cfg(feature = "lmdb")]
pub const DEFAULT_BACKEND: DatabaseBackend = DatabaseBackend::Lmdb;
#[cfg(not(any(feature = "mdbx", feature = "lmdb")))]
pub const DEFAULT_BACKEND: DatabaseBackend = DatabaseBackend::Disabled;

pub const MAX_HISTORY_LENGTH: usize = 1 << 16;
pub const MEGABYTE: usize = 1 << 20;
pub const MDBX_DATA_FILENAME: &str = "mdbx.dat";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_path: PathBuf,
    pub chunk_size: usize,
    pub validator_chunk_size: usize,
    /// Number of epochs of history to keep.
    pub history_length: usize,
    /// Update frequency in seconds.
    pub update_period: u64,
    /// Offset from the start of the slot to begin processing.
    pub slot_offset: f64,
    /// Maximum size of the database in megabytes.
    pub max_db_size_mbs: usize,
    /// Maximum size of the in-memory cache for attestation roots.
    pub attestation_root_cache_size: usize,
    /// Whether to broadcast slashings found to the network.
    pub broadcast: bool,
    /// Database backend to use.
    pub backend: DatabaseBackend,
}

/// Immutable configuration parameters which are stored on disk and checked for consistency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskConfig {
    pub chunk_size: usize,
    pub validator_chunk_size: usize,
    pub history_length: usize,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Display, EnumString, EnumVariantNames,
)]
#[strum(serialize_all = "lowercase")]
pub enum DatabaseBackend {
    #[cfg(feature = "mdbx")]
    Mdbx,
    #[cfg(feature = "lmdb")]
    Lmdb,
    Disabled,
}

#[derive(Debug, PartialEq)]
pub enum DatabaseBackendOverride {
    Success(DatabaseBackend),
    Failure(PathBuf),
    Noop,
}

impl Config {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            chunk_size: DEFAULT_CHUNK_SIZE,
            validator_chunk_size: DEFAULT_VALIDATOR_CHUNK_SIZE,
            history_length: DEFAULT_HISTORY_LENGTH,
            update_period: DEFAULT_UPDATE_PERIOD,
            slot_offset: DEFAULT_SLOT_OFFSET,
            max_db_size_mbs: DEFAULT_MAX_DB_SIZE,
            attestation_root_cache_size: DEFAULT_ATTESTATION_ROOT_CACHE_SIZE,
            broadcast: DEFAULT_BROADCAST,
            backend: DEFAULT_BACKEND,
        }
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
        } else if self.history_length > MAX_HISTORY_LENGTH {
            Err(Error::ConfigInvalidHistoryLength {
                history_length: self.history_length,
                max_history_length: MAX_HISTORY_LENGTH,
            })
        } else {
            Ok(())
        }
    }

    pub fn disk_config(&self) -> DiskConfig {
        DiskConfig {
            chunk_size: self.chunk_size,
            validator_chunk_size: self.validator_chunk_size,
            history_length: self.history_length,
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

    pub fn override_backend(&mut self) -> DatabaseBackendOverride {
        let mdbx_path = self.database_path.join(MDBX_DATA_FILENAME);

        #[cfg(feature = "mdbx")]
        let already_mdbx = self.backend == DatabaseBackend::Mdbx;
        #[cfg(not(feature = "mdbx"))]
        let already_mdbx = false;

        if !already_mdbx && mdbx_path.exists() {
            #[cfg(feature = "mdbx")]
            {
                let old_backend = self.backend;
                self.backend = DatabaseBackend::Mdbx;
                DatabaseBackendOverride::Success(old_backend)
            }
            #[cfg(not(feature = "mdbx"))]
            {
                DatabaseBackendOverride::Failure(mdbx_path)
            }
        } else {
            DatabaseBackendOverride::Noop
        }
    }
}
