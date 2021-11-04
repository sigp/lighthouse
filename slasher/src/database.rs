use crate::{
    utils::{TxnMapFull, TxnOptional},
    AttesterRecord, AttesterSlashingStatus, Config, Error, ProposerSlashingStatus,
};
use byteorder::{BigEndian, ByteOrder};
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use serde::Deserialize;
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{
    Epoch, EthSpec, Hash256, IndexedAttestation, ProposerSlashing, SignedBeaconBlockHeader, Slot,
};

/// Current database schema version, to check compatibility of on-disk DB with software.
pub const CURRENT_SCHEMA_VERSION: u64 = 3;

/// Metadata about the slashing database itself.
const METADATA_DB: &str = "metadata";
/// Map from `(target_epoch, validator_index)` to `AttesterRecord`.
const ATTESTERS_DB: &str = "attesters";
/// Companion database for the attesters DB mapping `validator_index` to largest `target_epoch`
/// stored for that validator in the attesters DB.
///
/// Used to implement wrap-around semantics for target epochs modulo the history length.
const ATTESTERS_MAX_TARGETS_DB: &str = "attesters_max_targets";
/// Map from `(target_epoch, indexed_attestation_hash)` to `IndexedAttestation`.
const INDEXED_ATTESTATION_DB: &str = "indexed_attestations";
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

/// The number of DBs for LMDB to use (equal to the number of DBs defined above).
const LMDB_MAX_DBS: u32 = 8;

/// Constant key under which the schema version is stored in the `metadata_db`.
const METADATA_VERSION_KEY: &[u8] = &[0];
/// Constant key under which the slasher configuration is stored in the `metadata_db`.
const METADATA_CONFIG_KEY: &[u8] = &[1];

const ATTESTER_KEY_SIZE: usize = 7;
const PROPOSER_KEY_SIZE: usize = 16;
const CURRENT_EPOCH_KEY_SIZE: usize = 8;
const INDEXED_ATTESTATION_KEY_SIZE: usize = 40;
const MEGABYTE: usize = 1 << 20;

#[derive(Debug)]
pub struct SlasherDB<E: EthSpec> {
    pub(crate) env: Environment,
    pub(crate) indexed_attestation_db: Database,
    pub(crate) attesters_db: Database,
    pub(crate) attesters_max_targets_db: Database,
    pub(crate) min_targets_db: Database,
    pub(crate) max_targets_db: Database,
    pub(crate) current_epochs_db: Database,
    pub(crate) proposers_db: Database,
    pub(crate) metadata_db: Database,
    config: Arc<Config>,
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

    pub fn parse(data: &[u8]) -> Result<(Slot, u64), Error> {
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
pub struct IndexedAttestationKey {
    target_and_root: [u8; INDEXED_ATTESTATION_KEY_SIZE],
}

impl IndexedAttestationKey {
    pub fn new(target_epoch: Epoch, indexed_attestation_root: Hash256) -> Self {
        let mut data = [0; INDEXED_ATTESTATION_KEY_SIZE];
        data[0..8].copy_from_slice(&target_epoch.as_u64().to_be_bytes());
        data[8..INDEXED_ATTESTATION_KEY_SIZE].copy_from_slice(indexed_attestation_root.as_bytes());
        Self {
            target_and_root: data,
        }
    }

    pub fn parse(data: &[u8]) -> Result<(Epoch, Hash256), Error> {
        if data.len() == INDEXED_ATTESTATION_KEY_SIZE {
            let target_epoch = Epoch::new(BigEndian::read_u64(&data[..8]));
            let indexed_attestation_root = Hash256::from_slice(&data[8..]);
            Ok((target_epoch, indexed_attestation_root))
        } else {
            Err(Error::IndexedAttestationKeyCorrupt { length: data.len() })
        }
    }
}

impl AsRef<[u8]> for IndexedAttestationKey {
    fn as_ref(&self) -> &[u8] {
        &self.target_and_root
    }
}

impl<E: EthSpec> SlasherDB<E> {
    pub fn open(config: Arc<Config>) -> Result<Self, Error> {
        std::fs::create_dir_all(&config.database_path)?;
        let env = Environment::new()
            .set_max_dbs(LMDB_MAX_DBS)
            .set_map_size(config.max_db_size_mbs * MEGABYTE)
            .open_with_permissions(&config.database_path, 0o600)?;
        let indexed_attestation_db =
            env.create_db(Some(INDEXED_ATTESTATION_DB), Self::db_flags())?;
        let attesters_db = env.create_db(Some(ATTESTERS_DB), Self::db_flags())?;
        let attesters_max_targets_db =
            env.create_db(Some(ATTESTERS_MAX_TARGETS_DB), Self::db_flags())?;
        let min_targets_db = env.create_db(Some(MIN_TARGETS_DB), Self::db_flags())?;
        let max_targets_db = env.create_db(Some(MAX_TARGETS_DB), Self::db_flags())?;
        let current_epochs_db = env.create_db(Some(CURRENT_EPOCHS_DB), Self::db_flags())?;
        let proposers_db = env.create_db(Some(PROPOSERS_DB), Self::db_flags())?;
        let metadata_db = env.create_db(Some(METADATA_DB), Self::db_flags())?;

        #[cfg(windows)]
        {
            use filesystem::restrict_file_permissions;
            let data = config.database_path.join("data.mdb");
            let lock = config.database_path.join("lock.mdb");
            restrict_file_permissions(data).map_err(Error::DatabasePermissionsError)?;
            restrict_file_permissions(lock).map_err(Error::DatabasePermissionsError)?;
        }

        let db = Self {
            env,
            indexed_attestation_db,
            attesters_db,
            attesters_max_targets_db,
            min_targets_db,
            max_targets_db,
            current_epochs_db,
            proposers_db,
            metadata_db,
            config,
            _phantom: PhantomData,
        };

        let mut txn = db.begin_rw_txn()?;

        db.migrate(&mut txn)?;

        if let Some(on_disk_config) = db.load_config(&mut txn)? {
            if !db.config.is_compatible(&on_disk_config) {
                return Err(Error::ConfigIncompatible {
                    on_disk_config,
                    config: (*db.config).clone(),
                });
            }
        }
        db.store_config(&db.config, &mut txn)?;
        txn.commit()?;

        Ok(db)
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

    pub fn load_schema_version(&self, txn: &mut RwTransaction<'_>) -> Result<Option<u64>, Error> {
        Ok(txn
            .get(self.metadata_db, &METADATA_VERSION_KEY)
            .optional()?
            .map(bincode::deserialize)
            .transpose()?)
    }

    pub fn store_schema_version(&self, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        txn.put(
            self.metadata_db,
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
    pub fn load_config<'a, T: Deserialize<'a>>(
        &self,
        txn: &'a mut RwTransaction<'_>,
    ) -> Result<Option<T>, Error> {
        Ok(txn
            .get(self.metadata_db, &METADATA_CONFIG_KEY)
            .optional()?
            .map(bincode::deserialize)
            .transpose()?)
    }

    pub fn store_config(&self, config: &Config, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        txn.put(
            self.metadata_db,
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
        Ok(txn
            .get(
                self.attesters_max_targets_db,
                &CurrentEpochKey::new(validator_index),
            )
            .optional()?
            .map(Epoch::from_ssz_bytes)
            .transpose()?)
    }

    pub fn update_attester_max_target(
        &self,
        validator_index: u64,
        previous_max_target: Epoch,
        max_target: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        // Zero out attester DB entries which are now older than the history length.
        // Avoid writing the whole array on initialization (previous_max_target == 0), and
        // avoid overwriting the entire attesters array more than once.
        if previous_max_target != 0 {
            let start_epoch = std::cmp::max(
                previous_max_target.as_u64() + 1,
                (max_target.as_u64() + 1).saturating_sub(self.config.history_length as u64),
            );
            for target_epoch in (start_epoch..max_target.as_u64()).map(Epoch::new) {
                txn.put(
                    self.attesters_db,
                    &AttesterKey::new(validator_index, target_epoch, &self.config),
                    &AttesterRecord::null().as_ssz_bytes(),
                    Self::write_flags(),
                )?;
            }
        }

        txn.put(
            self.attesters_max_targets_db,
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
        Ok(txn
            .get(
                self.current_epochs_db,
                &CurrentEpochKey::new(validator_index),
            )
            .optional()?
            .map(Epoch::from_ssz_bytes)
            .transpose()?)
    }

    pub fn update_current_epoch_for_validator(
        &self,
        validator_index: u64,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        txn.put(
            self.current_epochs_db,
            &CurrentEpochKey::new(validator_index),
            &current_epoch.as_ssz_bytes(),
            Self::write_flags(),
        )?;
        Ok(())
    }

    pub fn store_indexed_attestation(
        &self,
        txn: &mut RwTransaction<'_>,
        indexed_attestation_hash: Hash256,
        indexed_attestation: &IndexedAttestation<E>,
    ) -> Result<(), Error> {
        let key = IndexedAttestationKey::new(
            indexed_attestation.data.target.epoch,
            indexed_attestation_hash,
        );
        let data = indexed_attestation.as_ssz_bytes();

        txn.put(
            self.indexed_attestation_db,
            &key,
            &data,
            Self::write_flags(),
        )?;
        Ok(())
    }

    pub fn get_indexed_attestation(
        &self,
        txn: &mut RwTransaction<'_>,
        target_epoch: Epoch,
        indexed_attestation_hash: Hash256,
    ) -> Result<IndexedAttestation<E>, Error> {
        let key = IndexedAttestationKey::new(target_epoch, indexed_attestation_hash);
        let bytes = txn
            .get(self.indexed_attestation_db, &key)
            .optional()?
            .ok_or(Error::MissingIndexedAttestation {
                root: indexed_attestation_hash,
            })?;
        Ok(IndexedAttestation::from_ssz_bytes(bytes)?)
    }

    pub fn check_and_update_attester_record(
        &self,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        attestation: &IndexedAttestation<E>,
        record: AttesterRecord,
    ) -> Result<AttesterSlashingStatus<E>, Error> {
        // See if there's an existing attestation for this attester.
        let target_epoch = attestation.data.target.epoch;

        let current_epoch = self
            .get_attester_max_target(validator_index, txn)?
            .unwrap_or(Epoch::new(0));

        if let Some(existing_record) =
            self.get_attester_record(txn, validator_index, target_epoch, current_epoch)?
        {
            // If the existing attestation data is identical, then this attestation is not
            // slashable and no update is required.
            if existing_record.attestation_data_hash == record.attestation_data_hash {
                return Ok(AttesterSlashingStatus::NotSlashable);
            }

            // Otherwise, load the indexed attestation so we can confirm that it's slashable.
            let existing_attestation = self.get_indexed_attestation(
                txn,
                target_epoch,
                existing_record.indexed_attestation_hash,
            )?;
            if attestation.is_double_vote(&existing_attestation) {
                Ok(AttesterSlashingStatus::DoubleVote(Box::new(
                    existing_attestation,
                )))
            } else {
                Err(Error::AttesterRecordInconsistentRoot)
            }
        }
        // If no attestation exists, insert a record for this validator.
        else {
            if target_epoch > current_epoch {
                self.update_attester_max_target(validator_index, current_epoch, target_epoch, txn)?;
            }
            txn.put(
                self.attesters_db,
                &AttesterKey::new(validator_index, target_epoch, &self.config),
                &record.as_ssz_bytes(),
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
        let current_epoch = self
            .get_attester_max_target(validator_index, txn)?
            .unwrap_or(Epoch::new(0));

        let record = self
            .get_attester_record(txn, validator_index, target_epoch, current_epoch)?
            .ok_or(Error::MissingAttesterRecord {
                validator_index,
                target_epoch,
            })?;
        self.get_indexed_attestation(txn, target_epoch, record.indexed_attestation_hash)
    }

    pub fn get_attester_record(
        &self,
        txn: &mut RwTransaction<'_>,
        validator_index: u64,
        target: Epoch,
        current_epoch: Epoch,
    ) -> Result<Option<AttesterRecord>, Error> {
        if target > current_epoch {
            return Ok(None);
        }

        let attester_key = AttesterKey::new(validator_index, target, &self.config);
        Ok(txn
            .get(self.attesters_db, &attester_key)
            .optional()?
            .map(AttesterRecord::from_ssz_bytes)
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
        Ok(txn
            .get(self.proposers_db, &proposer_key)
            .optional()?
            .map(SignedBeaconBlockHeader::from_ssz_bytes)
            .transpose()?)
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
                self.proposers_db,
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

        let mut cursor = txn.open_rw_cursor(self.proposers_db)?;

        // Position cursor at first key, bailing out if the database is empty.
        if cursor
            .get(None, None, lmdb_sys::MDB_FIRST)
            .optional()?
            .is_none()
        {
            return Ok(());
        }

        loop {
            let key_bytes = cursor
                .get(None, None, lmdb_sys::MDB_GET_CURRENT)?
                .0
                .ok_or(Error::MissingProposerKey)?;

            let (slot, _) = ProposerKey::parse(key_bytes)?;
            if slot < min_slot {
                cursor.del(Self::write_flags())?;

                // End the loop if there is no next entry.
                if cursor
                    .get(None, None, lmdb_sys::MDB_NEXT)
                    .optional()?
                    .is_none()
                {
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

        let mut cursor = txn.open_rw_cursor(self.indexed_attestation_db)?;

        // Position cursor at first key, bailing out if the database is empty.
        if cursor
            .get(None, None, lmdb_sys::MDB_FIRST)
            .optional()?
            .is_none()
        {
            return Ok(());
        }

        loop {
            let key_bytes = cursor
                .get(None, None, lmdb_sys::MDB_GET_CURRENT)?
                .0
                .ok_or(Error::MissingAttesterKey)?;

            let (target_epoch, _) = IndexedAttestationKey::parse(key_bytes)?;

            if target_epoch < min_epoch {
                cursor.del(Self::write_flags())?;

                if cursor
                    .get(None, None, lmdb_sys::MDB_NEXT)
                    .optional()?
                    .is_none()
                {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(())
    }
}
