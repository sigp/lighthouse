use crate::config::MDBX_GROWTH_STEP;
use crate::{
    metrics, utils::TxnMapFull, AttesterRecord, AttesterSlashingStatus, CompactAttesterRecord,
    Config, Environment, Error, ProposerSlashingStatus, RwTransaction,
};
use byteorder::{BigEndian, ByteOrder};
use lru::LruCache;
use mdbx::{Database, DatabaseFlags, Geometry, WriteFlags};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use slog::{info, Logger};
use ssz::{Decode, Encode};
use std::borrow::{Borrow, Cow};
use std::marker::PhantomData;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    Epoch, EthSpec, Hash256, IndexedAttestation, ProposerSlashing, SignedBeaconBlockHeader, Slot,
};

/// Current database schema version, to check compatibility of on-disk DB with software.
pub const CURRENT_SCHEMA_VERSION: u64 = 3;

/// Metadata about the slashing database itself.
const METADATA_DB: &str = "metadata";
/// Map from `(target_epoch, validator_index)` to `CompactAttesterRecord`.
const ATTESTERS_DB: &str = "attesters";
/// Companion database for the attesters DB mapping `validator_index` to largest `target_epoch`
/// stored for that validator in the attesters DB.
///
/// Used to implement wrap-around semantics for target epochs modulo the history length.
const ATTESTERS_MAX_TARGETS_DB: &str = "attesters_max_targets";
/// Map from `indexed_attestation_id` to `IndexedAttestation`.
const INDEXED_ATTESTATION_DB: &str = "indexed_attestations";
/// Map from `(target_epoch, indexed_attestation_hash)` to `indexed_attestation_id`.
const INDEXED_ATTESTATION_ID_DB: &str = "indexed_attestation_ids";
/// Table of minimum targets for every source epoch within range.
const MIN_TARGETS_DB: &str = "min_targets";
/// Table of maximum targets for every source epoch within range.
const MAX_TARGETS_DB: &str = "max_targets";
/// Map from `validator_index` to the `current_epoch` for that validator.
///
/// Used to implement wrap-around semantics for the min and max target arrays.
const CURRENT_EPOCHS_DB: &str = "current_epochs";
/// Map from `(slot, validator_index)` to `SignedBeaconBlockHeader`.
const PROPOSERS_DB: &str = "proposers";

/// The number of DBs for MDBX to use (equal to the number of DBs defined above).
const MAX_NUM_DBS: usize = 9;

/// Filename for the legacy (LMDB) database file, so that it may be deleted.
const LEGACY_DB_FILENAME: &str = "data.mdb";
const LEGACY_DB_LOCK_FILENAME: &str = "lock.mdb";

/// Constant key under which the schema version is stored in the `metadata_db`.
const METADATA_VERSION_KEY: &[u8] = &[0];
/// Constant key under which the slasher configuration is stored in the `metadata_db`.
const METADATA_CONFIG_KEY: &[u8] = &[1];

const ATTESTER_KEY_SIZE: usize = 7;
const PROPOSER_KEY_SIZE: usize = 16;
const CURRENT_EPOCH_KEY_SIZE: usize = 8;
const INDEXED_ATTESTATION_ID_SIZE: usize = 6;
const INDEXED_ATTESTATION_ID_KEY_SIZE: usize = 40;
const MEGABYTE: usize = 1 << 20;

#[derive(Debug)]
pub struct SlasherDB<E: EthSpec> {
    pub(crate) env: Environment,
    /// LRU cache mapping indexed attestation IDs to their attestation data roots.
    attestation_root_cache: Mutex<LruCache<IndexedAttestationId, Hash256>>,
    pub(crate) config: Arc<Config>,
    _phantom: PhantomData<E>,
}

/// Database key for the `attesters` database.
///
/// Stored as big-endian `(target_epoch, validator_index)` to enable efficient iteration
/// while pruning.
///
/// The target epoch is stored in 2 bytes modulo the `history_length`.
///
/// The validator index is stored in 5 bytes (validator registry limit is 2^40).
#[derive(Debug)]
pub struct AttesterKey {
    data: [u8; ATTESTER_KEY_SIZE],
}

impl AttesterKey {
    pub fn new(validator_index: u64, target_epoch: Epoch, config: &Config) -> Self {
        let mut data = [0; ATTESTER_KEY_SIZE];

        BigEndian::write_uint(
            &mut data[..2],
            target_epoch.as_u64() % config.history_length as u64,
            2,
        );
        BigEndian::write_uint(&mut data[2..], validator_index, 5);

        AttesterKey { data }
    }
}

impl AsRef<[u8]> for AttesterKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Database key for the `proposers` database.
///
/// Stored as big-endian `(slot, validator_index)` to enable efficient iteration
/// while pruning.
#[derive(Debug)]
pub struct ProposerKey {
    data: [u8; PROPOSER_KEY_SIZE],
}

impl ProposerKey {
    pub fn new(validator_index: u64, slot: Slot) -> Self {
        let mut data = [0; PROPOSER_KEY_SIZE];
        data[0..8].copy_from_slice(&slot.as_u64().to_be_bytes());
        data[8..PROPOSER_KEY_SIZE].copy_from_slice(&validator_index.to_be_bytes());
        ProposerKey { data }
    }

    pub fn parse(data: Cow<[u8]>) -> Result<(Slot, u64), Error> {
        if data.len() == PROPOSER_KEY_SIZE {
            let slot = Slot::new(BigEndian::read_u64(&data[..8]));
            let validator_index = BigEndian::read_u64(&data[8..]);
            Ok((slot, validator_index))
        } else {
            Err(Error::ProposerKeyCorrupt { length: data.len() })
        }
    }
}

impl AsRef<[u8]> for ProposerKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Key containing a validator index
pub struct CurrentEpochKey {
    validator_index: [u8; CURRENT_EPOCH_KEY_SIZE],
}

impl CurrentEpochKey {
    pub fn new(validator_index: u64) -> Self {
        Self {
            validator_index: validator_index.to_be_bytes(),
        }
    }
}

impl AsRef<[u8]> for CurrentEpochKey {
    fn as_ref(&self) -> &[u8] {
        &self.validator_index
    }
}

/// Key containing an epoch and an indexed attestation hash.
pub struct IndexedAttestationIdKey {
    target_and_root: [u8; INDEXED_ATTESTATION_ID_KEY_SIZE],
}

impl IndexedAttestationIdKey {
    pub fn new(target_epoch: Epoch, indexed_attestation_root: Hash256) -> Self {
        let mut data = [0; INDEXED_ATTESTATION_ID_KEY_SIZE];
        data[0..8].copy_from_slice(&target_epoch.as_u64().to_be_bytes());
        data[8..INDEXED_ATTESTATION_ID_KEY_SIZE]
            .copy_from_slice(indexed_attestation_root.as_bytes());
        Self {
            target_and_root: data,
        }
    }

    pub fn parse(data: Cow<[u8]>) -> Result<(Epoch, Hash256), Error> {
        if data.len() == INDEXED_ATTESTATION_ID_KEY_SIZE {
            let target_epoch = Epoch::new(BigEndian::read_u64(&data[..8]));
            let indexed_attestation_root = Hash256::from_slice(&data[8..]);
            Ok((target_epoch, indexed_attestation_root))
        } else {
            Err(Error::IndexedAttestationIdKeyCorrupt { length: data.len() })
        }
    }
}

impl AsRef<[u8]> for IndexedAttestationIdKey {
    fn as_ref(&self) -> &[u8] {
        &self.target_and_root
    }
}

/// Key containing a 6-byte indexed attestation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexedAttestationId {
    id: [u8; INDEXED_ATTESTATION_ID_SIZE],
}

impl IndexedAttestationId {
    pub fn new(id: u64) -> Self {
        let mut data = [0; INDEXED_ATTESTATION_ID_SIZE];
        BigEndian::write_uint(&mut data, id, INDEXED_ATTESTATION_ID_SIZE);
        Self { id: data }
    }

    pub fn parse(data: Cow<[u8]>) -> Result<u64, Error> {
        if data.len() == INDEXED_ATTESTATION_ID_SIZE {
            Ok(BigEndian::read_uint(
                data.borrow(),
                INDEXED_ATTESTATION_ID_SIZE,
            ))
        } else {
            Err(Error::IndexedAttestationIdCorrupt { length: data.len() })
        }
    }

    pub fn null() -> Self {
        Self::new(0)
    }

    pub fn is_null(&self) -> bool {
        self.id == [0, 0, 0, 0, 0, 0]
    }

    pub fn as_u64(&self) -> u64 {
        BigEndian::read_uint(&self.id, INDEXED_ATTESTATION_ID_SIZE)
    }
}

impl AsRef<[u8]> for IndexedAttestationId {
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}

/// Bincode deserialization specialised to `Cow<[u8]>`.
fn bincode_deserialize<T: DeserializeOwned>(bytes: Cow<[u8]>) -> Result<T, Error> {
    Ok(bincode::deserialize(bytes.borrow())?)
}

fn ssz_decode<T: Decode>(bytes: Cow<[u8]>) -> Result<T, Error> {
    Ok(T::from_ssz_bytes(bytes.borrow())?)
}

impl<E: EthSpec> SlasherDB<E> {
    pub fn open(config: Arc<Config>, log: Logger) -> Result<Self, Error> {
        // Delete any legacy LMDB database.
        Self::delete_legacy_file(&config.database_path, LEGACY_DB_FILENAME, &log)?;
        Self::delete_legacy_file(&config.database_path, LEGACY_DB_LOCK_FILENAME, &log)?;

        std::fs::create_dir_all(&config.database_path)?;

        let env = Environment::new()
            .set_max_dbs(MAX_NUM_DBS)
            .set_geometry(Self::geometry(&config))
            .open_with_permissions(&config.database_path, 0o600)?;

        let txn = env.begin_rw_txn()?;
        txn.create_db(Some(INDEXED_ATTESTATION_DB), Self::db_flags())?;
        txn.create_db(Some(INDEXED_ATTESTATION_ID_DB), Self::db_flags())?;
        txn.create_db(Some(ATTESTERS_DB), Self::db_flags())?;
        txn.create_db(Some(ATTESTERS_MAX_TARGETS_DB), Self::db_flags())?;
        txn.create_db(Some(MIN_TARGETS_DB), Self::db_flags())?;
        txn.create_db(Some(MAX_TARGETS_DB), Self::db_flags())?;
        txn.create_db(Some(CURRENT_EPOCHS_DB), Self::db_flags())?;
        txn.create_db(Some(PROPOSERS_DB), Self::db_flags())?;
        txn.create_db(Some(METADATA_DB), Self::db_flags())?;
        txn.commit()?;

        #[cfg(windows)]
        {
            use filesystem::restrict_file_permissions;
            let data = config.database_path.join("mdbx.dat");
            let lock = config.database_path.join("mdbx.lck");
            restrict_file_permissions(data).map_err(Error::DatabasePermissionsError)?;
            restrict_file_permissions(lock).map_err(Error::DatabasePermissionsError)?;
        }

        let attestation_root_cache = Mutex::new(LruCache::new(config.attestation_root_cache_size));

        let mut db = Self {
            env,
            attestation_root_cache,
            config,
            _phantom: PhantomData,
        };

        db = db.migrate()?;

        let mut txn = db.begin_rw_txn()?;
        if let Some(on_disk_config) = db.load_config(&mut txn)? {
            let current_disk_config = db.config.disk_config();
            if current_disk_config != on_disk_config {
                return Err(Error::ConfigIncompatible {
                    on_disk_config,
                    config: current_disk_config,
                });
            }
        }
        txn.commit()?;

        Ok(db)
    }

    fn delete_legacy_file(slasher_dir: &Path, filename: &str, log: &Logger) -> Result<(), Error> {
        let path = slasher_dir.join(filename);

        if path.is_file() {
            info!(
                log,
                "Deleting legacy slasher DB";
                "file" => ?path.display(),
            );
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn open_db<'a>(&self, txn: &'a RwTransaction<'a>, name: &str) -> Result<Database<'a>, Error> {
        Ok(txn.open_db(Some(name))?)
    }

    pub fn indexed_attestation_db<'a>(
        &self,
        txn: &'a RwTransaction<'a>,
    ) -> Result<Database<'a>, Error> {
        self.open_db(txn, INDEXED_ATTESTATION_DB)
    }

    pub fn indexed_attestation_id_db<'a>(
        &self,
        txn: &'a RwTransaction<'a>,
    ) -> Result<Database<'a>, Error> {
        self.open_db(txn, INDEXED_ATTESTATION_ID_DB)
    }

    pub fn attesters_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, ATTESTERS_DB)
    }

    pub fn attesters_max_targets_db<'a>(
        &self,
        txn: &'a RwTransaction<'a>,
    ) -> Result<Database<'a>, Error> {
        self.open_db(txn, ATTESTERS_MAX_TARGETS_DB)
    }

    pub fn min_targets_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, MIN_TARGETS_DB)
    }

    pub fn max_targets_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, MAX_TARGETS_DB)
    }

    pub fn current_epochs_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, CURRENT_EPOCHS_DB)
    }

    pub fn proposers_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, PROPOSERS_DB)
    }

    pub fn metadata_db<'a>(&self, txn: &'a RwTransaction<'a>) -> Result<Database<'a>, Error> {
        self.open_db(txn, METADATA_DB)
    }

    pub fn db_flags() -> DatabaseFlags {
        DatabaseFlags::default()
    }

    pub fn write_flags() -> WriteFlags {
        WriteFlags::default()
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction<'_>, Error> {
        Ok(self.env.begin_rw_txn()?)
    }

    pub fn geometry(config: &Config) -> Geometry<Range<usize>> {
        Geometry {
            size: Some(0..config.max_db_size_mbs * MEGABYTE),
            growth_step: Some(MDBX_GROWTH_STEP),
            shrink_threshold: None,
            page_size: None,
        }
    }

    pub fn load_schema_version(&self, txn: &mut RwTransaction<'_>) -> Result<Option<u64>, Error> {
        txn.get(&self.metadata_db(txn)?, METADATA_VERSION_KEY)?
            .map(bincode_deserialize)
            .transpose()
    }

    pub fn store_schema_version(&self, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        txn.put(
            &self.metadata_db(txn)?,
            &METADATA_VERSION_KEY,
            &bincode::serialize(&CURRENT_SCHEMA_VERSION)?,
            Self::write_flags(),
        )?;
        Ok(())
    }

    /// Load a config from disk.
    ///
    /// This is generic in order to allow loading of configs for different schema versions.
    /// Care should be taken to ensure it is only called for `Config`-like `T`.
    pub fn load_config<T: DeserializeOwned>(
        &self,
        txn: &mut RwTransaction<'_>,
    ) -> Result<Option<T>, Error> {
        txn.get(&self.metadata_db(txn)?, METADATA_CONFIG_KEY)?
            .map(bincode_deserialize)
            .transpose()
    }

    pub fn store_config(&self, config: &Config, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        txn.put(
            &self.metadata_db(txn)?,
            &METADATA_CONFIG_KEY,
            &bincode::serialize(config)?,
            Self::write_flags(),
        )?;
        Ok(())
    }

    pub fn get_attester_max_target(
        &self,
        validator_index: u64,
        txn: &mut RwTransaction<'_>,
    ) -> Result<Option<Epoch>, Error> {
        txn.get(
            &self.attesters_max_targets_db(txn)?,
            CurrentEpochKey::new(validator_index).as_ref(),
        )?
        .map(ssz_decode)
        .transpose()
    }

    pub fn update_attester_max_target(
        &self,
        validator_index: u64,
        previous_max_target: Option<Epoch>,
        max_target: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        // Don't update maximum if new target is less than or equal to previous. In the case of
        // no previous we *do* want to update.
        if previous_max_target.map_or(false, |prev_max| max_target <= prev_max) {
            return Ok(());
        }

        // Zero out attester DB entries which are now older than the history length.
        // Avoid writing the whole array on initialization (`previous_max_target == None`), and
        // avoid overwriting the entire attesters array more than once.
        if let Some(previous_max_target) = previous_max_target {
            let start_epoch = std::cmp::max(
                previous_max_target.as_u64() + 1,
                (max_target.as_u64() + 1).saturating_sub(self.config.history_length as u64),
            );
            for target_epoch in (start_epoch..max_target.as_u64()).map(Epoch::new) {
                txn.put(
                    &self.attesters_db(txn)?,
                    &AttesterKey::new(validator_index, target_epoch, &self.config),
                    &CompactAttesterRecord::null().as_bytes(),
                    Self::write_flags(),
                )?;
            }
        }

        txn.put(
            &self.attesters_max_targets_db(txn)?,
            &CurrentEpochKey::new(validator_index),
            &max_target.as_ssz_bytes(),
            Self::write_flags(),
        )?;
        Ok(())
    }

    pub fn get_current_epoch_for_validator(
        &self,
        validator_index: u64,
        txn: &mut RwTransaction<'_>,
    ) -> Result<Option<Epoch>, Error> {
        txn.get(
            &self.current_epochs_db(txn)?,
            CurrentEpochKey::new(validator_index).as_ref(),
        )?
        .map(ssz_decode)
        .transpose()
    }

    pub fn update_current_epoch_for_validator(
        &self,
        validator_index: u64,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        txn.put(
            &self.current_epochs_db(txn)?,
            &CurrentEpochKey::new(validator_index),
            &current_epoch.as_ssz_bytes(),
            Self::write_flags(),
        )?;
        Ok(())
    }

    fn get_indexed_attestation_id(
        &self,
        txn: &mut RwTransaction<'_>,
        key: &IndexedAttestationIdKey,
    ) -> Result<Option<u64>, Error> {
        txn.get(&self.indexed_attestation_id_db(txn)?, key.as_ref())?
            .map(IndexedAttestationId::parse)
            .transpose()
    }

    fn put_indexed_attestation_id(
        &self,
        txn: &mut RwTransaction<'_>,
        key: &IndexedAttestationIdKey,
        value: IndexedAttestationId,
    ) -> Result<(), Error> {
        txn.put(
            &self.indexed_attestation_id_db(txn)?,
            key,
            &value,
            Self::write_flags(),
        )?;
        Ok(())
    }

    /// Store an indexed attestation and return its ID.
    ///
    /// If the attestation is already stored then the existing ID will be returned without a write.
    pub fn store_indexed_attestation(
        &self,
        txn: &mut RwTransaction<'_>,
        indexed_attestation_hash: Hash256,
        indexed_attestation: &IndexedAttestation<E>,
    ) -> Result<u64, Error> {
        // Look-up ID by hash.
        let id_key = IndexedAttestationIdKey::new(
            indexed_attestation.data.target.epoch,
            indexed_attestation_hash,
        );

        if let Some(indexed_att_id) = self.get_indexed_attestation_id(txn, &id_key)? {
            return Ok(indexed_att_id);
        }

        // Store the new indexed attestation at the end of the current table.
        let mut cursor = txn.cursor(&self.indexed_attestation_db(txn)?)?;

        let indexed_att_id = match cursor.last::<_, ()>()? {
            // First ID is 1 so that 0 can be used to represent `null` in `CompactAttesterRecord`.
            None => 1,
            Some((key_bytes, _)) => IndexedAttestationId::parse(key_bytes)? + 1,
        };

        let attestation_key = IndexedAttestationId::new(indexed_att_id);
        let data = indexed_attestation.as_ssz_bytes();

        cursor.put(attestation_key.as_ref(), &data, Self::write_flags())?;
        drop(cursor);

        // Update the (epoch, hash) to ID mapping.
        self.put_indexed_attestation_id(txn, &id_key, attestation_key)?;

        Ok(indexed_att_id)
    }

    pub fn get_indexed_attestation(
        &self,
        txn: &mut RwTransaction<'_>,
        indexed_attestation_id: IndexedAttestationId,
    ) -> Result<IndexedAttestation<E>, Error> {
        let bytes = txn
            .get(
                &self.indexed_attestation_db(txn)?,
                indexed_attestation_id.as_ref(),
            )?
            .ok_or(Error::MissingIndexedAttestation {
                id: indexed_attestation_id.as_u64(),
            })?;
        ssz_decode(bytes)
    }

    fn get_attestation_data_root(
        &self,
        txn: &mut RwTransaction<'_>,
        indexed_id: IndexedAttestationId,
    ) -> Result<(Hash256, Option<IndexedAttestation<E>>), Error> {
        metrics::inc_counter(&metrics::SLASHER_NUM_ATTESTATION_ROOT_QUERIES);

        // If the value already exists in the cache, return it.
        let mut cache = self.attestation_root_cache.lock();
        if let Some(attestation_data_root) = cache.get(&indexed_id) {
            metrics::inc_counter(&metrics::SLASHER_NUM_ATTESTATION_ROOT_HITS);
            return Ok((*attestation_data_root, None));
        }

        // Otherwise, load the indexed attestation, compute the root and cache it.
        let indexed_attestation = self.get_indexed_attestation(txn, indexed_id)?;
        let attestation_data_root = indexed_attestation.data.tree_hash_root();

        cache.put(indexed_id, attestation_data_root);

        Ok((attestation_data_root, Some(indexed_attestation)))
    }

    pub fn cache_attestation_data_root(
        &self,
        indexed_attestation_id: IndexedAttestationId,
        attestation_data_root: Hash256,
    ) {
        let mut cache = self.attestation_root_cache.lock();
        cache.put(indexed_attestation_id, attestation_data_root);
    }

    fn delete_attestation_data_roots(&self, ids: impl IntoIterator<Item = IndexedAttestationId>) {
        let mut cache = self.attestation_root_cache.lock();
        for indexed_id in ids {
            cache.pop(&indexed_id);
        }
    }

    pub fn attestation_root_cache_size(&self) -> usize {
        self.attestation_root_cache.lock().len()
    }

    pub fn check_and_update_attester_record(
        &self,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        attestation: &IndexedAttestation<E>,
        record: &AttesterRecord,
        indexed_attestation_id: IndexedAttestationId,
    ) -> Result<AttesterSlashingStatus<E>, Error> {
        // See if there's an existing attestation for this attester.
        let target_epoch = attestation.data.target.epoch;

        let prev_max_target = self.get_attester_max_target(validator_index, txn)?;

        if let Some(existing_record) =
            self.get_attester_record(txn, validator_index, target_epoch, prev_max_target)?
        {
            // If the existing indexed attestation is identical, then this attestation is not
            // slashable and no update is required.
            let existing_att_id = existing_record.indexed_attestation_id;
            if existing_att_id == indexed_attestation_id {
                return Ok(AttesterSlashingStatus::NotSlashable);
            }

            // Otherwise, load the attestation data root and check slashability via a hash root
            // comparison.
            let (existing_data_root, opt_existing_att) =
                self.get_attestation_data_root(txn, existing_att_id)?;

            if existing_data_root == record.attestation_data_hash {
                return Ok(AttesterSlashingStatus::NotSlashable);
            }

            // If we made it this far, then the attestation is slashable. Ensure that it's
            // loaded, double-check the slashing condition and return.
            let existing_attestation = opt_existing_att
                .map_or_else(|| self.get_indexed_attestation(txn, existing_att_id), Ok)?;

            if attestation.is_double_vote(&existing_attestation) {
                Ok(AttesterSlashingStatus::DoubleVote(Box::new(
                    existing_attestation,
                )))
            } else {
                Err(Error::InconsistentAttestationDataRoot)
            }
        }
        // If no attestation exists, insert a record for this validator.
        else {
            self.update_attester_max_target(validator_index, prev_max_target, target_epoch, txn)?;

            txn.put(
                &self.attesters_db(txn)?,
                &AttesterKey::new(validator_index, target_epoch, &self.config),
                &indexed_attestation_id,
                Self::write_flags(),
            )?;

            Ok(AttesterSlashingStatus::NotSlashable)
        }
    }

    pub fn get_attestation_for_validator(
        &self,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        target_epoch: Epoch,
    ) -> Result<IndexedAttestation<E>, Error> {
        let max_target = self.get_attester_max_target(validator_index, txn)?;

        let record = self
            .get_attester_record(txn, validator_index, target_epoch, max_target)?
            .ok_or(Error::MissingAttesterRecord {
                validator_index,
                target_epoch,
            })?;
        self.get_indexed_attestation(txn, record.indexed_attestation_id)
    }

    pub fn get_attester_record(
        &self,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        target: Epoch,
        prev_max_target: Option<Epoch>,
    ) -> Result<Option<CompactAttesterRecord>, Error> {
        if prev_max_target.map_or(true, |prev_max| target > prev_max) {
            return Ok(None);
        }

        let attester_key = AttesterKey::new(validator_index, target, &self.config);
        Ok(txn
            .get(&self.attesters_db(txn)?, attester_key.as_ref())?
            .map(CompactAttesterRecord::parse)
            .transpose()?
            .filter(|record| !record.is_null()))
    }

    pub fn get_block_proposal(
        &self,
        txn: &mut RwTransaction<'_>,
        proposer_index: u64,
        slot: Slot,
    ) -> Result<Option<SignedBeaconBlockHeader>, Error> {
        let proposer_key = ProposerKey::new(proposer_index, slot);
        txn.get(&self.proposers_db(txn)?, proposer_key.as_ref())?
            .map(ssz_decode)
            .transpose()
    }

    pub fn check_or_insert_block_proposal(
        &self,
        txn: &mut RwTransaction<'_>,
        block_header: SignedBeaconBlockHeader,
    ) -> Result<ProposerSlashingStatus, Error> {
        let proposer_index = block_header.message.proposer_index;
        let slot = block_header.message.slot;

        if let Some(existing_block) = self.get_block_proposal(txn, proposer_index, slot)? {
            if existing_block == block_header {
                Ok(ProposerSlashingStatus::NotSlashable)
            } else {
                Ok(ProposerSlashingStatus::DoubleVote(Box::new(
                    ProposerSlashing {
                        signed_header_1: existing_block,
                        signed_header_2: block_header,
                    },
                )))
            }
        } else {
            txn.put(
                &self.proposers_db(txn)?,
                &ProposerKey::new(proposer_index, slot),
                &block_header.as_ssz_bytes(),
                Self::write_flags(),
            )?;
            Ok(ProposerSlashingStatus::NotSlashable)
        }
    }

    /// Attempt to prune the database, deleting old blocks and attestations.
    pub fn prune(&self, current_epoch: Epoch) -> Result<(), Error> {
        let mut txn = self.begin_rw_txn()?;
        self.try_prune(current_epoch, &mut txn).allow_map_full()?;
        txn.commit()?;
        Ok(())
    }

    /// Try to prune the database.
    ///
    /// This is a separate method from `prune` so that `allow_map_full` may be used.
    pub fn try_prune(
        &self,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        self.prune_proposers(current_epoch, txn)?;
        self.prune_indexed_attestations(current_epoch, txn)?;
        Ok(())
    }

    fn prune_proposers(
        &self,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        let min_slot = current_epoch
            .saturating_add(1u64)
            .saturating_sub(self.config.history_length)
            .start_slot(E::slots_per_epoch());

        let mut cursor = txn.cursor(&self.proposers_db(txn)?)?;

        // Position cursor at first key, bailing out if the database is empty.
        if cursor.first::<(), ()>()?.is_none() {
            return Ok(());
        }

        loop {
            let (key_bytes, ()) = cursor.get_current()?.ok_or(Error::MissingProposerKey)?;

            let (slot, _) = ProposerKey::parse(key_bytes)?;
            if slot < min_slot {
                cursor.del(Self::write_flags())?;

                // End the loop if there is no next entry.
                if cursor.next::<(), ()>()?.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(())
    }

    fn prune_indexed_attestations(
        &self,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        let min_epoch = current_epoch
            .saturating_add(1u64)
            .saturating_sub(self.config.history_length as u64);

        // Collect indexed attestation IDs to delete.
        let mut indexed_attestation_ids = vec![];

        let mut cursor = txn.cursor(&self.indexed_attestation_id_db(txn)?)?;

        // Position cursor at first key, bailing out if the database is empty.
        if cursor.first::<(), ()>()?.is_none() {
            return Ok(());
        }

        loop {
            let (key_bytes, value) = cursor
                .get_current()?
                .ok_or(Error::MissingIndexedAttestationIdKey)?;

            let (target_epoch, _) = IndexedAttestationIdKey::parse(key_bytes)?;

            if target_epoch < min_epoch {
                indexed_attestation_ids.push(IndexedAttestationId::new(
                    IndexedAttestationId::parse(value)?,
                ));

                cursor.del(Self::write_flags())?;

                if cursor.next::<(), ()>()?.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        drop(cursor);

        // Delete the indexed attestations.
        // Optimisation potential: use a cursor here.
        let indexed_attestation_db = self.indexed_attestation_db(txn)?;
        for indexed_attestation_id in &indexed_attestation_ids {
            txn.del(&indexed_attestation_db, indexed_attestation_id, None)?;
        }
        self.delete_attestation_data_roots(indexed_attestation_ids);

        Ok(())
    }
}
