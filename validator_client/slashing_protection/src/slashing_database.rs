use crate::interchange::{
    Interchange, InterchangeData, InterchangeMetadata, SignedAttestation as InterchangeAttestation,
    SignedBlock as InterchangeBlock,
};
use crate::signed_attestation::InvalidAttestation;
use crate::signed_block::InvalidBlock;
use crate::{signing_root_from_row, NotSafe, Safe, SignedAttestation, SignedBlock, SigningRoot};
use filesystem::restrict_file_permissions;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::fs::File;
use std::path::Path;
use std::time::Duration;
use types::{AttestationData, BeaconBlockHeader, Epoch, Hash256, PublicKeyBytes, SignedRoot, Slot};

type Pool = r2d2::Pool<SqliteConnectionManager>;

/// We set the pool size to 1 for compatibility with locking_mode=EXCLUSIVE.
///
/// This is perhaps overkill in the presence of exclusive transactions, but has
/// the added bonus of preventing other processes from trying to use our slashing database.
pub const POOL_SIZE: u32 = 1;
#[cfg(not(test))]
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const CONNECTION_TIMEOUT: Duration = Duration::from_millis(100);

/// Supported version of the interchange format.
pub const SUPPORTED_INTERCHANGE_FORMAT_VERSION: u64 = 5;

/// Column ID of the `validators.enabled` column.
pub const VALIDATORS_ENABLED_CID: i64 = 2;

#[derive(Debug, Clone)]
pub struct SlashingDatabase {
    conn_pool: Pool,
}

impl SlashingDatabase {
    /// Open an existing database at the given `path`, or create one if none exists.
    pub fn open_or_create(path: &Path) -> Result<Self, NotSafe> {
        if path.exists() {
            Self::open(path)
        } else {
            Self::create(path)
        }
    }

    /// Create a slashing database at the given path.
    ///
    /// Error if a database (or any file) already exists at `path`.
    pub fn create(path: &Path) -> Result<Self, NotSafe> {
        let _file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;

        restrict_file_permissions(path).map_err(|_| NotSafe::PermissionsError)?;
        let conn_pool = Self::open_conn_pool(path)?;
        let mut conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE validators (
                id INTEGER PRIMARY KEY,
                public_key BLOB NOT NULL UNIQUE
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE signed_blocks (
                validator_id INTEGER NOT NULL,
                slot INTEGER NOT NULL,
                signing_root BLOB NOT NULL,
                FOREIGN KEY(validator_id) REFERENCES validators(id)
                UNIQUE (validator_id, slot)
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE signed_attestations (
                validator_id INTEGER,
                source_epoch INTEGER NOT NULL,
                target_epoch INTEGER NOT NULL,
                signing_root BLOB NOT NULL,
                FOREIGN KEY(validator_id) REFERENCES validators(id)
                UNIQUE (validator_id, target_epoch)
            )",
            params![],
        )?;

        // The tables created above are for the v0 schema. We immediately update them
        // to the latest schema without dropping the connection.
        let txn = conn.transaction()?;
        Self::apply_schema_migrations(&txn)?;
        txn.commit()?;

        Ok(Self { conn_pool })
    }

    /// Open an existing `SlashingDatabase` from disk.
    ///
    /// This will automatically check for and apply the latest schema migrations.
    pub fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn_pool = Self::open_conn_pool(path)?;
        let db = Self { conn_pool };
        db.with_transaction(Self::apply_schema_migrations)?;
        Ok(db)
    }

    fn apply_schema_migrations(txn: &Transaction) -> Result<(), NotSafe> {
        // Add the `enabled` column to the `validators` table if it does not already exist.
        let enabled_col_exists = txn
            .query_row(
                "SELECT cid, name FROM pragma_table_info('validators') WHERE name = 'enabled'",
                params![],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .map(|(cid, name): (i64, String)| {
                // Check that the enabled column is in the correct position with the right name.
                // This is a defensive check that shouldn't do anything in practice unless the
                // slashing DB has been manually edited.
                if cid == VALIDATORS_ENABLED_CID && name == "enabled" {
                    Ok(())
                } else {
                    Err(NotSafe::ConsistencyError)
                }
            })
            .transpose()?
            .is_some();

        if !enabled_col_exists {
            txn.execute(
                "ALTER TABLE validators ADD COLUMN enabled BOOL NOT NULL DEFAULT TRUE",
                params![],
            )?;
        }

        Ok(())
    }

    /// Open a new connection pool with all of the necessary settings and tweaks.
    fn open_conn_pool(path: &Path) -> Result<Pool, NotSafe> {
        let manager = SqliteConnectionManager::file(path)
            .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .with_init(Self::apply_pragmas);
        let conn_pool = Pool::builder()
            .max_size(POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .build(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;
        Ok(conn_pool)
    }

    /// Apply the necessary settings to an SQLite connection.
    ///
    /// Most importantly, put the database into exclusive locking mode, so that threads are forced
    /// to serialise all DB access (to prevent slashable data being checked and signed in parallel).
    /// The exclusive locking mode also has the benefit of applying to other processes, so multiple
    /// Lighthouse processes trying to access the same database will also be blocked.
    fn apply_pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        Ok(())
    }

    /// Creates an empty transaction and drops it. Used to test whether the database is locked.
    pub fn test_transaction(&self) -> Result<(), NotSafe> {
        let mut conn = self.conn_pool.get()?;
        Transaction::new(&mut conn, TransactionBehavior::Exclusive)?;
        Ok(())
    }

    /// Execute a database transaction as a closure, committing if `f` returns `Ok`.
    pub fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Transaction) -> Result<T, E>,
        E: From<NotSafe>,
    {
        let mut conn = self.conn_pool.get().map_err(NotSafe::from)?;
        let txn = conn.transaction().map_err(NotSafe::from)?;
        let value = f(&txn)?;
        txn.commit().map_err(NotSafe::from)?;
        Ok(value)
    }

    /// Register a validator with the slashing protection database.
    ///
    /// This allows the validator to record their signatures in the database, and check
    /// for slashings.
    pub fn register_validator(&self, validator_pk: PublicKeyBytes) -> Result<(), NotSafe> {
        self.register_validators(std::iter::once(&validator_pk))
    }

    /// Register multiple validators with the slashing protection database.
    pub fn register_validators<'a>(
        &self,
        public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
    ) -> Result<(), NotSafe> {
        self.with_transaction(|txn| self.register_validators_in_txn(public_keys, txn))
    }

    /// Register multiple validators inside the given transaction.
    ///
    /// The caller must commit the transaction for the changes to be persisted.
    pub fn register_validators_in_txn<'a>(
        &self,
        public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let mut stmt =
            txn.prepare("INSERT INTO validators (public_key, enabled) VALUES (?1, TRUE)")?;
        for pubkey in public_keys {
            match self.get_validator_id_with_status(txn, pubkey)? {
                None => {
                    stmt.execute([pubkey.as_hex_string()])?;
                }
                Some((validator_id, false)) => {
                    self.update_validator_status(txn, validator_id, true)?;
                }
                Some((_, true)) => {
                    // Validator already registered and enabled.
                }
            }
        }
        Ok(())
    }

    pub fn update_validator_status(
        &self,
        txn: &Transaction,
        validator_id: i64,
        status: bool,
    ) -> Result<(), NotSafe> {
        txn.execute(
            "UPDATE validators SET enabled = ? WHERE id = ?",
            params![status, validator_id],
        )?;
        Ok(())
    }

    /// Check that all of the given validators are registered.
    pub fn check_validator_registrations<'a>(
        &self,
        mut public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
    ) -> Result<(), NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        public_keys
            .try_for_each(|public_key| self.get_validator_id_in_txn(&txn, public_key).map(|_| ()))
    }

    /// List the internal validator ID and public key of every registered validator.
    pub fn list_all_registered_validators(
        &self,
        txn: &Transaction,
    ) -> Result<Vec<(i64, PublicKeyBytes)>, InterchangeError> {
        txn.prepare("SELECT id, public_key FROM validators ORDER BY id ASC")?
            .query_and_then(params![], |row| {
                let validator_id = row.get(0)?;
                let pubkey_str: String = row.get(1)?;
                let pubkey = pubkey_str
                    .parse()
                    .map_err(InterchangeError::InvalidPubkey)?;
                Ok((validator_id, pubkey))
            })?
            .collect()
    }

    /// Get the database-internal ID for an enabled validator.
    ///
    /// This is NOT the same as a validator index, and depends on the ordering that validators
    /// are registered with the slashing protection database (and may vary between machines).
    pub fn get_validator_id(&self, public_key: &PublicKeyBytes) -> Result<i64, NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        self.get_validator_id_in_txn(&txn, public_key)
    }

    pub fn get_validator_id_in_txn(
        &self,
        txn: &Transaction,
        public_key: &PublicKeyBytes,
    ) -> Result<i64, NotSafe> {
        let (validator_id, enabled) = self
            .get_validator_id_with_status(txn, public_key)?
            .ok_or(NotSafe::UnregisteredValidator(*public_key))?;
        if enabled {
            Ok(validator_id)
        } else {
            Err(NotSafe::DisabledValidator(*public_key))
        }
    }

    /// Get validator ID regardless of whether or not it is enabled.
    pub fn get_validator_id_ignoring_status(
        &self,
        txn: &Transaction,
        public_key: &PublicKeyBytes,
    ) -> Result<i64, NotSafe> {
        let (validator_id, _) = self
            .get_validator_id_with_status(txn, public_key)?
            .ok_or(NotSafe::UnregisteredValidator(*public_key))?;
        Ok(validator_id)
    }

    pub fn get_validator_id_with_status(
        &self,
        txn: &Transaction,
        public_key: &PublicKeyBytes,
    ) -> Result<Option<(i64, bool)>, NotSafe> {
        Ok(txn
            .query_row(
                "SELECT id, enabled FROM validators WHERE public_key = ?1",
                params![&public_key.as_hex_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Check a block proposal from `validator_pubkey` for slash safety.
    fn check_block_proposal(
        &self,
        txn: &Transaction,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        signing_root: SigningRoot,
    ) -> Result<Safe, NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, validator_pubkey)?;

        let existing_block = txn
            .prepare(
                "SELECT slot, signing_root
                 FROM signed_blocks
                 WHERE validator_id = ?1 AND slot = ?2",
            )?
            .query_row(params![validator_id, slot], SignedBlock::from_row)
            .optional()?;

        if let Some(existing_block) = existing_block {
            if existing_block.signing_root == signing_root {
                // Same slot and same hash -> we're re-broadcasting a previously signed block
                return Ok(Safe::SameData);
            } else {
                // Same epoch but not the same hash -> it's a DoubleBlockProposal
                return Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    existing_block,
                )));
            }
        }

        let min_slot = txn
            .prepare("SELECT MIN(slot) FROM signed_blocks WHERE validator_id = ?1")?
            .query_row(params![validator_id], |row| row.get(0))?;

        if let Some(min_slot) = min_slot {
            if slot <= min_slot {
                return Err(NotSafe::InvalidBlock(
                    InvalidBlock::SlotViolatesLowerBound {
                        block_slot: slot,
                        bound_slot: min_slot,
                    },
                ));
            }
        }

        Ok(Safe::Valid)
    }

    /// Check an attestation from `validator_pubkey` for slash safety.
    fn check_attestation(
        &self,
        txn: &Transaction,
        validator_pubkey: &PublicKeyBytes,
        att_source_epoch: Epoch,
        att_target_epoch: Epoch,
        att_signing_root: SigningRoot,
    ) -> Result<Safe, NotSafe> {
        // Although it's not required to avoid slashing, we disallow attestations
        // which are obviously invalid by virtue of their source epoch exceeding their target.
        if att_source_epoch > att_target_epoch {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SourceExceedsTarget,
            ));
        }

        let validator_id = self.get_validator_id_in_txn(txn, validator_pubkey)?;

        // Check for a double vote. Namely, an existing attestation with the same target epoch,
        // and a different signing root.
        let same_target_att = txn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND target_epoch = ?2",
            )?
            .query_row(
                params![validator_id, att_target_epoch],
                SignedAttestation::from_row,
            )
            .optional()?;

        if let Some(existing_attestation) = same_target_att {
            // If the new attestation is identical to the existing attestation, then we already
            // know that it is safe, and can return immediately.
            if existing_attestation.signing_root == att_signing_root {
                return Ok(Safe::SameData);
            // Otherwise if the hashes are different, this is a double vote.
            } else {
                return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                    existing_attestation,
                )));
            }
        }

        // Check that no previous vote is surrounding `attestation`.
        // If there is a surrounding attestation, we only return the most recent one.
        let surrounding_attestation = txn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND source_epoch < ?2 AND target_epoch > ?3
                 ORDER BY target_epoch DESC
                 LIMIT 1",
            )?
            .query_row(
                params![validator_id, att_source_epoch, att_target_epoch],
                SignedAttestation::from_row,
            )
            .optional()?;

        if let Some(prev) = surrounding_attestation {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::PrevSurroundsNew { prev },
            ));
        }

        // Check that no previous vote is surrounded by `attestation`.
        // If there is a surrounded attestation, we only return the most recent one.
        let surrounded_attestation = txn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND source_epoch > ?2 AND target_epoch < ?3
                 ORDER BY target_epoch DESC
                 LIMIT 1",
            )?
            .query_row(
                params![validator_id, att_source_epoch, att_target_epoch],
                SignedAttestation::from_row,
            )
            .optional()?;

        if let Some(prev) = surrounded_attestation {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::NewSurroundsPrev { prev },
            ));
        }

        // Check lower bounds: ensure that source is greater than or equal to min source,
        // and target is greater than min target. This allows pruning, and compatibility
        // with the interchange format.
        let min_source = txn
            .prepare("SELECT MIN(source_epoch) FROM signed_attestations WHERE validator_id = ?1")?
            .query_row(params![validator_id], |row| row.get(0))?;

        if let Some(min_source) = min_source {
            if att_source_epoch < min_source {
                return Err(NotSafe::InvalidAttestation(
                    InvalidAttestation::SourceLessThanLowerBound {
                        source_epoch: att_source_epoch,
                        bound_epoch: min_source,
                    },
                ));
            }
        }

        let min_target = txn
            .prepare("SELECT MIN(target_epoch) FROM signed_attestations WHERE validator_id = ?1")?
            .query_row(params![validator_id], |row| row.get(0))?;

        if let Some(min_target) = min_target {
            if att_target_epoch <= min_target {
                return Err(NotSafe::InvalidAttestation(
                    InvalidAttestation::TargetLessThanOrEqLowerBound {
                        target_epoch: att_target_epoch,
                        bound_epoch: min_target,
                    },
                ));
            }
        }

        // Everything has been checked, return Valid
        Ok(Safe::Valid)
    }

    /// Insert a block proposal into the slashing database.
    ///
    /// This should *only* be called in the same (exclusive) transaction as `check_block_proposal`
    /// so that the check isn't invalidated by a concurrent mutation.
    fn insert_block_proposal(
        &self,
        txn: &Transaction,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        signing_root: SigningRoot,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, validator_pubkey)?;

        txn.execute(
            "INSERT INTO signed_blocks (validator_id, slot, signing_root)
             VALUES (?1, ?2, ?3)",
            params![validator_id, slot, signing_root.to_hash256_raw().as_bytes()],
        )?;
        Ok(())
    }

    /// Insert an attestation into the slashing database.
    ///
    /// This should *only* be called in the same (exclusive) transaction as `check_attestation`
    /// so that the check isn't invalidated by a concurrent mutation.
    fn insert_attestation(
        &self,
        txn: &Transaction,
        validator_pubkey: &PublicKeyBytes,
        att_source_epoch: Epoch,
        att_target_epoch: Epoch,
        att_signing_root: SigningRoot,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, validator_pubkey)?;

        txn.execute(
            "INSERT INTO signed_attestations (validator_id, source_epoch, target_epoch, signing_root)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                validator_id,
                att_source_epoch,
                att_target_epoch,
                att_signing_root.to_hash256_raw().as_bytes()
            ],
        )?;
        Ok(())
    }

    /// Check a block proposal for slash safety, and if it is safe, record it in the database.
    ///
    /// The checking and inserting happen atomically and exclusively. We enforce exclusivity
    /// to prevent concurrent checks and inserts from resulting in slashable data being inserted.
    ///
    /// This is the safe, externally-callable interface for checking block proposals.
    pub fn check_and_insert_block_proposal(
        &self,
        validator_pubkey: &PublicKeyBytes,
        block_header: &BeaconBlockHeader,
        domain: Hash256,
    ) -> Result<Safe, NotSafe> {
        self.check_and_insert_block_signing_root(
            validator_pubkey,
            block_header.slot,
            block_header.signing_root(domain).into(),
        )
    }

    /// As for `check_and_insert_block_proposal` but without requiring the whole `BeaconBlockHeader`.
    pub fn check_and_insert_block_signing_root(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        signing_root: SigningRoot,
    ) -> Result<Safe, NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        let safe = self.check_and_insert_block_signing_root_txn(
            validator_pubkey,
            slot,
            signing_root,
            &txn,
        )?;
        txn.commit()?;
        Ok(safe)
    }

    /// Transactional variant of `check_and_insert_block_signing_root`.
    pub fn check_and_insert_block_signing_root_txn(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        signing_root: SigningRoot,
        txn: &Transaction,
    ) -> Result<Safe, NotSafe> {
        let safe = self.check_block_proposal(txn, validator_pubkey, slot, signing_root)?;

        if safe != Safe::SameData {
            self.insert_block_proposal(txn, validator_pubkey, slot, signing_root)?;
        }
        Ok(safe)
    }

    /// Check an attestation for slash safety, and if it is safe, record it in the database.
    ///
    /// The checking and inserting happen atomically and exclusively. We enforce exclusivity
    /// to prevent concurrent checks and inserts from resulting in slashable data being inserted.
    ///
    /// This is the safe, externally-callable interface for checking attestations.
    pub fn check_and_insert_attestation(
        &self,
        validator_pubkey: &PublicKeyBytes,
        attestation: &AttestationData,
        domain: Hash256,
    ) -> Result<Safe, NotSafe> {
        let attestation_signing_root = attestation.signing_root(domain).into();
        self.check_and_insert_attestation_signing_root(
            validator_pubkey,
            attestation.source.epoch,
            attestation.target.epoch,
            attestation_signing_root,
        )
    }

    /// As for `check_and_insert_attestation` but without requiring the whole `AttestationData`.
    pub fn check_and_insert_attestation_signing_root(
        &self,
        validator_pubkey: &PublicKeyBytes,
        att_source_epoch: Epoch,
        att_target_epoch: Epoch,
        att_signing_root: SigningRoot,
    ) -> Result<Safe, NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        let safe = self.check_and_insert_attestation_signing_root_txn(
            validator_pubkey,
            att_source_epoch,
            att_target_epoch,
            att_signing_root,
            &txn,
        )?;
        txn.commit()?;
        Ok(safe)
    }

    /// Transactional variant of `check_and_insert_attestation_signing_root`.
    fn check_and_insert_attestation_signing_root_txn(
        &self,
        validator_pubkey: &PublicKeyBytes,
        att_source_epoch: Epoch,
        att_target_epoch: Epoch,
        att_signing_root: SigningRoot,
        txn: &Transaction,
    ) -> Result<Safe, NotSafe> {
        let safe = self.check_attestation(
            txn,
            validator_pubkey,
            att_source_epoch,
            att_target_epoch,
            att_signing_root,
        )?;

        if safe != Safe::SameData {
            self.insert_attestation(
                txn,
                validator_pubkey,
                att_source_epoch,
                att_target_epoch,
                att_signing_root,
            )?;
        }
        Ok(safe)
    }

    /// Import slashing protection from another client in the interchange format.
    ///
    /// This function will atomically import the entire interchange, failing if *any*
    /// record cannot be imported.
    pub fn import_interchange_info(
        &self,
        interchange: Interchange,
        genesis_validators_root: Hash256,
    ) -> Result<Vec<InterchangeImportOutcome>, InterchangeError> {
        let version = interchange.metadata.interchange_format_version;
        if version != SUPPORTED_INTERCHANGE_FORMAT_VERSION {
            return Err(InterchangeError::UnsupportedVersion(version));
        }

        if genesis_validators_root != interchange.metadata.genesis_validators_root {
            return Err(InterchangeError::GenesisValidatorsMismatch {
                client: genesis_validators_root,
                interchange_file: interchange.metadata.genesis_validators_root,
            });
        }

        // Create a single transaction for the entire batch, which will only be committed if
        // all records are imported successfully.
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;

        let mut import_outcomes = vec![];
        let mut commit = true;

        for record in interchange.data {
            let pubkey = record.pubkey;
            match self.import_interchange_record(record, &txn) {
                Ok(summary) => {
                    import_outcomes.push(InterchangeImportOutcome::Success { pubkey, summary });
                }
                Err(error) => {
                    import_outcomes.push(InterchangeImportOutcome::Failure { pubkey, error });
                    commit = false;
                }
            }
        }

        if commit {
            txn.commit()?;
            Ok(import_outcomes)
        } else {
            Err(InterchangeError::AtomicBatchAborted(import_outcomes))
        }
    }

    pub fn import_interchange_record(
        &self,
        record: InterchangeData,
        txn: &Transaction,
    ) -> Result<ValidatorSummary, NotSafe> {
        let pubkey = &record.pubkey;

        self.register_validators_in_txn(std::iter::once(pubkey), txn)?;

        // Summary of minimum and maximum messages pre-import.
        let prev_summary = self.validator_summary(pubkey, txn)?;

        // If the interchange contains any blocks, update the database with the new max slot.
        let max_block = record.signed_blocks.iter().max_by_key(|b| b.slot);

        if let Some(max_block) = max_block {
            // Store new synthetic block with maximum slot and null signing root. Remove all other
            // blocks.
            let new_max_slot = max_or(prev_summary.max_block_slot, max_block.slot);
            let signing_root = SigningRoot::default();

            self.clear_signed_blocks(pubkey, txn)?;
            self.insert_block_proposal(txn, pubkey, new_max_slot, signing_root)?;
        }

        // Find the attestations with max source and max target. Unless the input contains slashable
        // data these two attestations should be identical, but we also handle the case where they
        // are not.
        let max_source_attestation = record
            .signed_attestations
            .iter()
            .max_by_key(|att| att.source_epoch);
        let max_target_attestation = record
            .signed_attestations
            .iter()
            .max_by_key(|att| att.target_epoch);

        if let (Some(max_source_att), Some(max_target_att)) =
            (max_source_attestation, max_target_attestation)
        {
            let source_epoch = max_or(
                prev_summary.max_attestation_source,
                max_source_att.source_epoch,
            );
            let target_epoch = max_or(
                prev_summary.max_attestation_target,
                max_target_att.target_epoch,
            );
            let signing_root = SigningRoot::default();

            // Clear existing attestations before insert to avoid running afoul of the target epoch
            // uniqueness constraint.
            self.clear_signed_attestations(pubkey, txn)?;
            self.insert_attestation(txn, pubkey, source_epoch, target_epoch, signing_root)?;
        }

        let summary = self.validator_summary(&record.pubkey, txn)?;

        // Check that the summary is consistent with having added the new data.
        if summary.check_block_consistency(&prev_summary, !record.signed_blocks.is_empty())
            && summary.check_attestation_consistency(
                &prev_summary,
                !record.signed_attestations.is_empty(),
            )
        {
            Ok(summary)
        } else {
            // This should never occur and is indicative of a bug in the import code.
            Err(NotSafe::ConsistencyError)
        }
    }

    pub fn export_all_interchange_info(
        &self,
        genesis_validators_root: Hash256,
    ) -> Result<Interchange, InterchangeError> {
        self.export_interchange_info(genesis_validators_root, None)
    }

    pub fn export_interchange_info(
        &self,
        genesis_validators_root: Hash256,
        selected_pubkeys: Option<&[PublicKeyBytes]>,
    ) -> Result<Interchange, InterchangeError> {
        let mut conn = self.conn_pool.get()?;
        let txn = &conn.transaction()?;
        self.export_interchange_info_in_txn(genesis_validators_root, selected_pubkeys, txn)
    }

    pub fn export_interchange_info_in_txn(
        &self,
        genesis_validators_root: Hash256,
        selected_pubkeys: Option<&[PublicKeyBytes]>,
        txn: &Transaction,
    ) -> Result<Interchange, InterchangeError> {
        // Determine the validator IDs and public keys to export data for.
        let to_export = if let Some(selected_pubkeys) = selected_pubkeys {
            selected_pubkeys
                .iter()
                .map(|pubkey| {
                    let id = self.get_validator_id_ignoring_status(txn, pubkey)?;
                    Ok((id, *pubkey))
                })
                .collect::<Result<_, InterchangeError>>()?
        } else {
            self.list_all_registered_validators(txn)?
        };

        let data = to_export
            .into_iter()
            .map(|(validator_id, pubkey)| {
                let signed_blocks =
                    self.export_interchange_blocks_for_validator(validator_id, txn)?;
                let signed_attestations =
                    self.export_interchange_attestations_for_validator(validator_id, txn)?;
                Ok(InterchangeData {
                    pubkey,
                    signed_blocks,
                    signed_attestations,
                })
            })
            .collect::<Result<_, InterchangeError>>()?;

        let metadata = InterchangeMetadata {
            interchange_format_version: SUPPORTED_INTERCHANGE_FORMAT_VERSION,
            genesis_validators_root,
        };

        Ok(Interchange { metadata, data })
    }

    fn export_interchange_blocks_for_validator(
        &self,
        validator_id: i64,
        txn: &Transaction,
    ) -> Result<Vec<InterchangeBlock>, InterchangeError> {
        txn.prepare(
            "SELECT slot, signing_root
             FROM signed_blocks
             WHERE signed_blocks.validator_id = ?1
             ORDER BY slot ASC",
        )?
        .query_and_then(params![validator_id], |row| {
            let slot = row.get(0)?;
            let signing_root = signing_root_from_row(1, row)?.to_hash256();
            Ok(InterchangeBlock { slot, signing_root })
        })?
        .collect()
    }

    fn export_interchange_attestations_for_validator(
        &self,
        validator_id: i64,
        txn: &Transaction,
    ) -> Result<Vec<InterchangeAttestation>, InterchangeError> {
        txn.prepare(
            "SELECT source_epoch, target_epoch, signing_root
             FROM signed_attestations
             WHERE signed_attestations.validator_id = ?1
             ORDER BY source_epoch ASC, target_epoch ASC",
        )?
        .query_and_then(params![validator_id], |row| {
            let source_epoch = row.get(0)?;
            let target_epoch = row.get(1)?;
            let signing_root = signing_root_from_row(2, row)?.to_hash256();
            let signed_attestation = InterchangeAttestation {
                source_epoch,
                target_epoch,
                signing_root,
            };
            Ok(signed_attestation)
        })?
        .collect()
    }

    /// Remove all blocks for `public_key` with slots less than `new_min_slot`.
    fn prune_signed_blocks(
        &self,
        public_key: &PublicKeyBytes,
        new_min_slot: Slot,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, public_key)?;

        txn.execute(
            "DELETE FROM signed_blocks
             WHERE
                validator_id = ?1 AND
                slot < ?2 AND
                slot < (SELECT MAX(slot)
                        FROM signed_blocks
                        WHERE validator_id = ?1)",
            params![validator_id, new_min_slot],
        )?;

        Ok(())
    }

    /// Prune the signed blocks table for the given public keys.
    pub fn prune_all_signed_blocks<'a>(
        &self,
        mut public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
        new_min_slot: Slot,
    ) -> Result<(), NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        public_keys.try_for_each(|pubkey| self.prune_signed_blocks(pubkey, new_min_slot, &txn))?;
        txn.commit()?;
        Ok(())
    }

    /// Remove all attestations for `public_key` with `target < new_min_target`.
    ///
    /// If the `new_min_target` was plucked out of thin air and doesn't necessarily correspond to
    /// an extant attestation then this function is still safe. It will never delete *all* the
    /// attestations in the database.
    fn prune_signed_attestations(
        &self,
        public_key: &PublicKeyBytes,
        new_min_target: Epoch,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, public_key)?;

        // The following holds, because we never store mutually slashable attestations:
        //   a.target < new_min_target --> a.source <= new_min_source
        //
        // The `MAX(target_epoch)` acts as a guard to prevent accidentally clearing the DB.
        txn.execute(
            "DELETE FROM signed_attestations
             WHERE
                validator_id = ?1 AND
                target_epoch < ?2 AND
                target_epoch < (SELECT MAX(target_epoch)
                                FROM signed_attestations
                                WHERE validator_id = ?1)",
            params![validator_id, new_min_target],
        )?;

        Ok(())
    }

    /// Remove all attestations signed by a given `public_key`.
    ///
    /// This function is incredibly dangerous and should be used with extreme caution. Presently
    /// we only use it one place: immediately before inserting a new maximum source/maximum target
    /// attestation. Any future use should take care to respect the database's non-emptiness.
    fn clear_signed_attestations(
        &self,
        public_key: &PublicKeyBytes,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, public_key)?;

        txn.execute(
            "DELETE FROM signed_attestations WHERE validator_id = ?1",
            params![validator_id],
        )?;
        Ok(())
    }

    /// Remove all blocks signed by a given `public_key`.
    ///
    /// Dangerous, should only be used immediately before inserting a new block in the same
    /// transacation.
    fn clear_signed_blocks(
        &self,
        public_key: &PublicKeyBytes,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, public_key)?;
        txn.execute(
            "DELETE FROM signed_blocks WHERE validator_id = ?1",
            params![validator_id],
        )?;
        Ok(())
    }

    /// Prune the signed attestations table for the given validator keys.
    pub fn prune_all_signed_attestations<'a>(
        &self,
        mut public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
        new_min_target: Epoch,
    ) -> Result<(), NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        public_keys
            .try_for_each(|pubkey| self.prune_signed_attestations(pubkey, new_min_target, &txn))?;
        txn.commit()?;
        Ok(())
    }

    pub fn num_validator_rows(&self) -> Result<u32, NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        let count = txn
            .prepare("SELECT COALESCE(COUNT(*), 0) FROM validators")?
            .query_row(params![], |row| row.get(0))?;
        Ok(count)
    }

    /// Get a summary of a validator's slashing protection data including minimums and maximums.
    pub fn validator_summary(
        &self,
        public_key: &PublicKeyBytes,
        txn: &Transaction,
    ) -> Result<ValidatorSummary, NotSafe> {
        let validator_id = self.get_validator_id_in_txn(txn, public_key)?;
        let (min_block_slot, max_block_slot) = txn
            .prepare(
                "SELECT MIN(slot), MAX(slot)
                 FROM signed_blocks
                 WHERE validator_id = ?1",
            )?
            .query_row(params![validator_id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let (
            min_attestation_source,
            min_attestation_target,
            max_attestation_source,
            max_attestation_target,
        ) = txn
            .prepare(
                "SELECT MIN(source_epoch), MIN(target_epoch), MAX(source_epoch), MAX(target_epoch)
                 FROM signed_attestations
                 WHERE validator_id = ?1",
            )?
            .query_row(params![validator_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;

        Ok(ValidatorSummary {
            min_block_slot,
            max_block_slot,
            min_attestation_source,
            min_attestation_target,
            max_attestation_source,
            max_attestation_target,
        })
    }
}

/// Minimum and maximum slots and epochs signed by a validator.
#[derive(Debug)]
pub struct ValidatorSummary {
    pub min_block_slot: Option<Slot>,
    pub max_block_slot: Option<Slot>,
    pub min_attestation_source: Option<Epoch>,
    pub min_attestation_target: Option<Epoch>,
    pub max_attestation_source: Option<Epoch>,
    pub max_attestation_target: Option<Epoch>,
}

impl ValidatorSummary {
    fn check_block_consistency(&self, prev: &Self, imported_blocks: bool) -> bool {
        if imported_blocks {
            // Max block slot should be monotonically increasing and non-null.
            // Minimum should match maximum due to pruning.
            monotonic(self.max_block_slot, prev.max_block_slot)
                && self.min_block_slot == self.max_block_slot
        } else {
            // Block slots should be unchanged.
            prev.min_block_slot == self.min_block_slot && prev.max_block_slot == self.max_block_slot
        }
    }

    fn check_attestation_consistency(&self, prev: &Self, imported_attestations: bool) -> bool {
        if imported_attestations {
            // Max source and target epochs should be monotically increasing and non-null.
            // Minimums should match maximums due to pruning.
            monotonic(self.max_attestation_source, prev.max_attestation_source)
                && monotonic(self.max_attestation_target, prev.max_attestation_target)
                && self.min_attestation_source == self.max_attestation_source
                && self.min_attestation_target == self.max_attestation_target
        } else {
            // Attestation epochs should be unchanged.
            self.min_attestation_source == prev.min_attestation_source
                && self.max_attestation_source == prev.max_attestation_source
                && self.min_attestation_target == prev.min_attestation_target
                && self.max_attestation_target == prev.max_attestation_target
        }
    }
}

/// Take the maximum of `opt_x` and `y`, returning `y` if `opt_x` is `None`.
fn max_or<T: Copy + Ord>(opt_x: Option<T>, y: T) -> T {
    opt_x.map_or(y, |x| std::cmp::max(x, y))
}

/// Check that `new` is `Some` and greater than or equal to prev.
///
/// If prev is `None` and `new` is `Some` then `true` is returned.
fn monotonic<T: PartialOrd>(new: Option<T>, prev: Option<T>) -> bool {
    new.map_or(false, |new_val| {
        prev.map_or(true, |prev_val| new_val >= prev_val)
    })
}

/// The result of importing a single entry from an interchange file.
#[derive(Debug)]
pub enum InterchangeImportOutcome {
    Success {
        pubkey: PublicKeyBytes,
        summary: ValidatorSummary,
    },
    Failure {
        pubkey: PublicKeyBytes,
        error: NotSafe,
    },
}

impl InterchangeImportOutcome {
    pub fn failed(&self) -> bool {
        matches!(self, InterchangeImportOutcome::Failure { .. })
    }
}

#[derive(Debug)]
pub enum InterchangeError {
    UnsupportedVersion(u64),
    GenesisValidatorsMismatch {
        interchange_file: Hash256,
        client: Hash256,
    },
    MaxInconsistent,
    SummaryInconsistent,
    SQLError(String),
    SQLPoolError(r2d2::Error),
    SerdeJsonError(serde_json::Error),
    InvalidPubkey(String),
    NotSafe(NotSafe),
    AtomicBatchAborted(Vec<InterchangeImportOutcome>),
}

impl From<NotSafe> for InterchangeError {
    fn from(error: NotSafe) -> Self {
        InterchangeError::NotSafe(error)
    }
}

impl From<rusqlite::Error> for InterchangeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::SQLError(error.to_string())
    }
}

impl From<r2d2::Error> for InterchangeError {
    fn from(error: r2d2::Error) -> Self {
        InterchangeError::SQLPoolError(error)
    }
}

impl From<serde_json::Error> for InterchangeError {
    fn from(error: serde_json::Error) -> Self {
        InterchangeError::SerdeJsonError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_non_existent_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");
        assert!(SlashingDatabase::open(&file).is_err());
    }

    // Due to the exclusive locking, trying to use an already open database should error.
    #[test]
    fn double_open_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");
        let _db1 = SlashingDatabase::create(&file).unwrap();

        SlashingDatabase::open(&file).unwrap_err();
    }

    // Attempting to create the same database twice should error.
    #[test]
    fn double_create_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");
        let _db1 = SlashingDatabase::create(&file).unwrap();
        drop(_db1);
        SlashingDatabase::create(&file).unwrap_err();
    }

    // Check that both `open` and `create` apply the same connection settings.
    #[test]
    fn connection_settings_applied() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");

        let check = |db: &SlashingDatabase| {
            assert_eq!(db.conn_pool.max_size(), POOL_SIZE);
            assert_eq!(db.conn_pool.connection_timeout(), CONNECTION_TIMEOUT);
            let conn = db.conn_pool.get().unwrap();
            assert!(conn
                .pragma_query_value(None, "foreign_keys", |row| { row.get::<_, bool>(0) })
                .unwrap());
            assert_eq!(
                conn.pragma_query_value(None, "locking_mode", |row| { row.get::<_, String>(0) })
                    .unwrap()
                    .to_uppercase(),
                "EXCLUSIVE"
            );
        };

        let db1 = SlashingDatabase::create(&file).unwrap();
        check(&db1);
        drop(db1);
        let db2 = SlashingDatabase::open(&file).unwrap();
        check(&db2);
    }

    #[test]
    fn test_transaction_failure() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");
        let db = SlashingDatabase::create(&file).unwrap();

        db.with_transaction(|_| {
            db.test_transaction().unwrap_err();
            Ok::<(), NotSafe>(())
        })
        .unwrap();
    }
}
