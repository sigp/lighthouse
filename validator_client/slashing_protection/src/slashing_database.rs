use crate::interchange::{
    Interchange, InterchangeData, InterchangeMetadata, SignedAttestation as InterchangeAttestation,
    SignedBlock as InterchangeBlock,
};
use crate::signed_attestation::InvalidAttestation;
use crate::signed_block::InvalidBlock;
use crate::{hash256_from_row, NotSafe, Safe, SignedAttestation, SignedBlock, SigningRoot};
use filesystem::restrict_file_permissions;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::fs::OpenOptions;
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
        let _file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;

        restrict_file_permissions(path).map_err(|_| NotSafe::PermissionsError)?;
        let conn_pool = Self::open_conn_pool(path)?;
        let conn = conn_pool.get()?;

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

        Ok(Self { conn_pool })
    }

    /// Open an existing `SlashingDatabase` from disk.
    pub fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn_pool = Self::open_conn_pool(&path)?;
        Ok(Self { conn_pool })
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
        conn.pragma_update(None, "foreign_keys", &true)?;
        conn.pragma_update(None, "locking_mode", &"EXCLUSIVE")?;
        Ok(())
    }

    /// Creates an empty transaction and drops it. Used to test whether the database is locked.
    pub fn test_transaction(&self) -> Result<(), NotSafe> {
        let mut conn = self.conn_pool.get()?;
        Transaction::new(&mut conn, TransactionBehavior::Exclusive)?;
        Ok(())
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
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        self.register_validators_in_txn(public_keys, &txn)?;
        txn.commit()?;
        Ok(())
    }

    /// Register multiple validators inside the given transaction.
    ///
    /// The caller must commit the transaction for the changes to be persisted.
    pub fn register_validators_in_txn<'a>(
        &self,
        public_keys: impl Iterator<Item = &'a PublicKeyBytes>,
        txn: &Transaction,
    ) -> Result<(), NotSafe> {
        let mut stmt = txn.prepare("INSERT INTO validators (public_key) VALUES (?1)")?;
        for pubkey in public_keys {
            if self.get_validator_id_opt(&txn, pubkey)?.is_none() {
                stmt.execute(&[pubkey.to_hex_string()])?;
            }
        }
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

    /// Get the database-internal ID for a validator.
    ///
    /// This is NOT the same as a validator index, and depends on the ordering that validators
    /// are registered with the slashing protection database (and may vary between machines).
    pub fn get_validator_id(&self, public_key: &PublicKeyBytes) -> Result<i64, NotSafe> {
        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;
        self.get_validator_id_in_txn(&txn, public_key)
    }

    fn get_validator_id_in_txn(
        &self,
        txn: &Transaction,
        public_key: &PublicKeyBytes,
    ) -> Result<i64, NotSafe> {
        self.get_validator_id_opt(txn, public_key)?
            .ok_or_else(|| NotSafe::UnregisteredValidator(*public_key))
    }

    /// Optional version of `get_validator_id`.
    fn get_validator_id_opt(
        &self,
        txn: &Transaction,
        public_key: &PublicKeyBytes,
    ) -> Result<Option<i64>, NotSafe> {
        Ok(txn
            .query_row(
                "SELECT id FROM validators WHERE public_key = ?1",
                params![&public_key.to_hex_string()],
                |row| row.get(0),
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
            params![validator_id, slot, signing_root.to_hash256().as_bytes()],
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
                att_signing_root.to_hash256().as_bytes()
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
        let safe = self.check_block_proposal(&txn, validator_pubkey, slot, signing_root)?;

        if safe != Safe::SameData {
            self.insert_block_proposal(&txn, validator_pubkey, slot, signing_root)?;
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
            &txn,
            validator_pubkey,
            att_source_epoch,
            att_target_epoch,
            att_signing_root,
        )?;

        if safe != Safe::SameData {
            self.insert_attestation(
                &txn,
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
    /// Return a vector of public keys and errors for any validators whose data could not be
    /// imported.
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

        let mut conn = self.conn_pool.get()?;

        let mut import_outcomes = vec![];

        for record in interchange.data {
            let pubkey = record.pubkey;
            let txn = conn.transaction()?;
            match self.import_interchange_record(record, &txn) {
                Ok(summary) => {
                    import_outcomes.push(InterchangeImportOutcome::Success { pubkey, summary });
                    txn.commit()?;
                }
                Err(error) => {
                    import_outcomes.push(InterchangeImportOutcome::Failure { pubkey, error });
                }
            }
        }

        Ok(import_outcomes)
    }

    pub fn import_interchange_record(
        &self,
        mut record: InterchangeData,
        txn: &Transaction,
    ) -> Result<ValidatorSummary, NotSafe> {
        self.register_validators_in_txn(std::iter::once(&record.pubkey), txn)?;

        // Insert all signed blocks, sorting them so that the minimum bounds are not
        // violated by blocks earlier in the file.
        record.signed_blocks.sort_unstable_by_key(|b| b.slot);
        for block in &record.signed_blocks {
            self.check_and_insert_block_signing_root_txn(
                &record.pubkey,
                block.slot,
                block
                    .signing_root
                    .map(SigningRoot::from)
                    .unwrap_or_default(),
                txn,
            )?;
        }

        // Prune blocks less than the min slot from this interchange file.
        // This ensures we don't sign anything less than the min slot after successful import,
        // which is signficant if we have imported two files with a "gap" in between.
        if let Some(new_min_slot) = record.signed_blocks.iter().map(|block| block.slot).min() {
            self.prune_signed_blocks(&record.pubkey, new_min_slot, txn)?;
        }

        // Insert all signed attestations.
        record
            .signed_attestations
            .sort_unstable_by_key(|att| (att.source_epoch, att.target_epoch));
        for attestation in &record.signed_attestations {
            self.check_and_insert_attestation_signing_root_txn(
                &record.pubkey,
                attestation.source_epoch,
                attestation.target_epoch,
                attestation
                    .signing_root
                    .map(SigningRoot::from)
                    .unwrap_or_default(),
                txn,
            )?;
        }

        // Prune attestations less than the min target from this interchange file.
        // See the rationale for blocks above, and the doc comment for `prune_signed_attestations`
        // for why we don't need to separately prune for the min source.
        if let Some(new_min_target) = record
            .signed_attestations
            .iter()
            .map(|attestation| attestation.target_epoch)
            .min()
        {
            self.prune_signed_attestations(&record.pubkey, new_min_target, txn)?;
        }

        let summary = self.validator_summary(&record.pubkey, txn)?;

        Ok(summary)
    }

    pub fn export_interchange_info(
        &self,
        genesis_validators_root: Hash256,
    ) -> Result<Interchange, InterchangeError> {
        use std::collections::BTreeMap;

        let mut conn = self.conn_pool.get()?;
        let txn = conn.transaction()?;

        // Map from internal validator pubkey to blocks and attestation for that pubkey.
        let mut data: BTreeMap<String, (Vec<InterchangeBlock>, Vec<InterchangeAttestation>)> =
            BTreeMap::new();

        txn.prepare(
            "SELECT public_key, slot, signing_root
             FROM signed_blocks, validators
             WHERE signed_blocks.validator_id = validators.id
             ORDER BY slot ASC",
        )?
        .query_and_then(params![], |row| {
            let validator_pubkey: String = row.get(0)?;
            let slot = row.get(1)?;
            let signing_root = Some(hash256_from_row(2, &row)?);
            let signed_block = InterchangeBlock { slot, signing_root };
            data.entry(validator_pubkey)
                .or_insert_with(|| (vec![], vec![]))
                .0
                .push(signed_block);
            Ok(())
        })?
        .collect::<Result<_, InterchangeError>>()?;

        txn.prepare(
            "SELECT public_key, source_epoch, target_epoch, signing_root
             FROM signed_attestations, validators
             WHERE signed_attestations.validator_id = validators.id
             ORDER BY source_epoch ASC, target_epoch ASC",
        )?
        .query_and_then(params![], |row| {
            let validator_pubkey: String = row.get(0)?;
            let source_epoch = row.get(1)?;
            let target_epoch = row.get(2)?;
            let signing_root = Some(hash256_from_row(3, &row)?);
            let signed_attestation = InterchangeAttestation {
                source_epoch,
                target_epoch,
                signing_root,
            };
            data.entry(validator_pubkey)
                .or_insert_with(|| (vec![], vec![]))
                .1
                .push(signed_attestation);
            Ok(())
        })?
        .collect::<Result<_, InterchangeError>>()?;

        let metadata = InterchangeMetadata {
            interchange_format_version: SUPPORTED_INTERCHANGE_FORMAT_VERSION,
            genesis_validators_root,
        };

        let data = data
            .into_iter()
            .map(|(pubkey, (signed_blocks, signed_attestations))| {
                Ok(InterchangeData {
                    pubkey: pubkey.parse().map_err(InterchangeError::InvalidPubkey)?,
                    signed_blocks,
                    signed_attestations,
                })
            })
            .collect::<Result<_, InterchangeError>>()?;

        Ok(Interchange { metadata, data })
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
    /// Pruning every attestation with target less than `new_min_target` also has the effect of
    /// making the new minimum source the source of the attestation with `target == new_min_target`
    /// (if any exists). This is exactly what's required for pruning after importing an interchange
    /// file, whereby we want to update the new minimum source to the min source from the
    /// interchange.
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

        // The following holds:
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

    /// Get a summary of a validator's slashing protection data for consumption by the user.
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
    MinimalAttestationSourceAndTargetInconsistent,
    SQLError(String),
    SQLPoolError(r2d2::Error),
    SerdeJsonError(serde_json::Error),
    InvalidPubkey(String),
    NotSafe(NotSafe),
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
    use crate::test_utils::pubkey;
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

        let db2 = SlashingDatabase::open(&file).unwrap();
        db2.register_validator(pubkey(0)).unwrap_err();
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
            assert_eq!(
                conn.pragma_query_value(None, "foreign_keys", |row| { row.get::<_, bool>(0) })
                    .unwrap(),
                true
            );
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
        let _db1 = SlashingDatabase::create(&file).unwrap();

        let db2 = SlashingDatabase::open(&file).unwrap();
        db2.test_transaction().unwrap_err();
    }
}
