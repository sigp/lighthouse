use crate::signed_attestation::InvalidAttestation;
use crate::signed_block::InvalidBlock;
use crate::{NotSafe, Safe, SignedAttestation, SignedBlock};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use std::fs::{File, OpenOptions};
use std::path::Path;
use tree_hash::TreeHash;
use types::{AttestationData, BeaconBlockHeader, Hash256, PublicKey};

type Pool = r2d2::Pool<SqliteConnectionManager>;
type Connection = PooledConnection<SqliteConnectionManager>;

#[derive(Debug, Clone)]
pub struct SlashingDatabase {
    conn_pool: Pool,
}

impl SlashingDatabase {
    pub fn open_or_create(path: &Path) -> Result<Self, NotSafe> {
        if path.exists() {
            Self::open(path)
        } else {
            Self::create(path)
        }
    }

    /// Create a slashing database at the given path, if none exists.
    pub fn create(path: &Path) -> Result<Self, NotSafe> {
        // Create all tables
        // TODO: could consider using `create_new`, atm `create` is required by tempfile tests
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)?;

        Self::set_db_file_permissions(&file)?;

        let manager = SqliteConnectionManager::file(path).with_init(Self::apply_pragmas);
        let conn_pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;

        let conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE validators (
                id INTEGER PRIMARY KEY,
                public_key BLOB NOT NULL
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
        let manager = SqliteConnectionManager::file(path).with_init(Self::apply_pragmas);
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;
        Ok(Self { conn_pool })
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

    /// Set the database file to readable and writable only by its owner (0600).
    #[cfg(unix)]
    fn set_db_file_permissions(file: &File) -> Result<(), NotSafe> {
        use std::os::unix::fs::PermissionsExt;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;
        Ok(())
    }

    // TODO: add support for Windows ACLs
    #[cfg(windows)]
    fn set_db_file_permissions(file: &File) -> Result<(), NotSafe> {}

    /// Register a validator with the slashing protection database.
    ///
    /// This allows the validator to record their signatures in the database, and check
    /// for slashings.
    pub fn register_validator(&self, validator_pk: &PublicKey) -> Result<(), NotSafe> {
        let conn = self.conn_pool.get()?;
        self.register_validator_from_conn(&conn, validator_pk)
    }

    fn register_validator_from_conn(
        &self,
        conn: &Connection,
        validator_pk: &PublicKey,
    ) -> Result<(), NotSafe> {
        conn.execute(
            "INSERT INTO validators (public_key) VALUES (?1)",
            params![validator_pk.as_hex_string()],
        )?;

        Ok(())
    }

    fn get_validator_id(connection: &Connection, public_key: &PublicKey) -> Result<i64, NotSafe> {
        connection
            .query_row(
                "SELECT id FROM validators WHERE public_key = ?1",
                params![&public_key.as_hex_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| NotSafe::UnregisteredValidator(public_key.clone()))
    }

    fn check_block_proposal(
        &self,
        conn: &Connection,
        validator_pubkey: &PublicKey,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        let existing_block = conn
            .prepare(
                "SELECT slot, signing_root
                 FROM signed_blocks
                 WHERE validator_id = ?1 AND slot = ?2",
            )?
            .query_row(
                params![validator_id, block_header.slot],
                SignedBlock::from_row,
            )
            .optional()?;

        if let Some(existing_block) = existing_block {
            if existing_block.signing_root == block_header.canonical_root() {
                // Same slot and same hash -> we're re-broadcasting a previously signed block
                Ok(Safe::SameData)
            } else {
                // Same epoch but not the same hash -> it's a DoubleBlockProposal
                Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    existing_block,
                )))
            }
        } else {
            Ok(Safe::Valid)
        }
    }

    fn check_attestation(
        &self,
        conn: &Connection,
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<Safe, NotSafe> {
        let att_source_epoch = attestation.source.epoch;
        let att_target_epoch = attestation.target.epoch;

        // Although it's not required to avoid slashing, we disallow attestations
        // which are obviously invalid by virtue of their source epoch exceeding their target.
        if att_source_epoch > att_target_epoch {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SourceExceedsTarget,
            ));
        }

        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        // 1. Check for a double vote. Namely, an existing attestation with the same target epoch,
        //    and a different signing root.
        let same_target_att = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND target_epoch = ?2",
            )?
            .query_row(params![validator_id, att_target_epoch], |row| {
                let source_epoch = row.get(0)?;
                let target_epoch = row.get(1)?;
                let root: Vec<u8> = row.get(2)?;
                let signing_root = Hash256::from_slice(&root[..]);
                Ok(SignedAttestation::new(
                    source_epoch,
                    target_epoch,
                    signing_root,
                ))
            })
            .optional()?;

        if let Some(existing_attestation) = same_target_att {
            // If the new attestation is identical to the existing attestation, then we already
            // know that it is safe, and can return immediately.
            if existing_attestation.signing_root == attestation.tree_hash_root() {
                return Ok(Safe::SameData);
            // Otherwise if the hashes are different, this is a double vote.
            } else {
                return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                    existing_attestation,
                )));
            }
        }

        // 2. Check that no previous vote is surrounding `attestation`.
        // If there is a surrounding attestation, we only return the most recent one.
        let surrounding_attestation = conn
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

        // 3. Check that no previous vote is surrounded by `attestation`.
        // If there is a surrounded attestation, we only return the most recent one.
        let surrounded_attestation = conn
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

        // Everything has been checked, return Valid
        Ok(Safe::Valid)
    }

    fn insert_block_proposal(
        &self,
        conn: &Connection,
        validator_pubkey: &PublicKey,
        block_header: &BeaconBlockHeader,
    ) -> Result<(), NotSafe> {
        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        conn.execute(
            "INSERT INTO signed_blocks (validator_id, slot, signing_root)
             VALUES (?1, ?2, ?3)",
            params![
                validator_id,
                block_header.slot,
                block_header.canonical_root().as_bytes()
            ],
        )?;
        Ok(())
    }

    fn insert_attestation(
        &self,
        conn: &Connection,
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<(), NotSafe> {
        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        conn.execute(
            "INSERT INTO signed_attestations (validator_id, source_epoch, target_epoch, signing_root)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                validator_id,
                attestation.source.epoch,
                attestation.target.epoch,
                attestation.tree_hash_root().as_bytes()
            ],
        )?;
        Ok(())
    }

    pub fn check_and_insert_block_proposal(
        &self,
        validator_pubkey: &PublicKey,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        let conn = self.conn_pool.get()?;

        match self.check_block_proposal(&conn, validator_pubkey, block_header) {
            Ok(Safe::SameData) => Ok(Safe::SameData),
            Ok(Safe::Valid) => self
                .insert_block_proposal(&conn, validator_pubkey, block_header)
                .map(|()| Safe::Valid),
            Err(notsafe) => Err(notsafe),
        }
    }

    pub fn check_and_insert_attestation(
        &self,
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<Safe, NotSafe> {
        let conn = self.conn_pool.get()?;

        match self.check_attestation(&conn, validator_pubkey, attestation) {
            Ok(Safe::SameData) => Ok(Safe::SameData),
            Ok(Safe::Valid) => self
                .insert_attestation(&conn, validator_pubkey, attestation)
                .map(|()| Safe::Valid),
            Err(notsafe) => Err(notsafe),
        }
    }
}
