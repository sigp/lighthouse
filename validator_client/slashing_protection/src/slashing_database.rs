use crate::signed_attestation::InvalidAttestation;
use crate::signed_block::InvalidBlock;
use crate::{NotSafe, Safe, SignedAttestation, SignedBlock, ValidityReason};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use std::fs::OpenOptions;
use std::path::Path;
use types::{AttestationData, BeaconBlockHeader, Hash256, PublicKey};
// FIXME(slashing): remove UNIX dependency
use std::os::unix::fs::PermissionsExt;
use tree_hash::TreeHash;

type Pool = r2d2::Pool<SqliteConnectionManager>;

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
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;

        let manager = SqliteConnectionManager::file(path)
            .with_init(|conn| conn.pragma_update(None, "foreign_keys", &true));
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;

        let conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE validators (
                id INTEGER PRIMARY KEY,
                public_key BLOB NOT NULL
            )",
            params![],
        )?;

        // FIXME(slashing): consider unique (validator_id, slot)
        conn.execute(
            "CREATE TABLE signed_blocks (
                validator_id INTEGER NOT NULL,
                slot INTEGER NOT NULL,
                signing_root BLOB NOT NULL,
                FOREIGN KEY(validator_id) REFERENCES validators(id)
            )",
            params![],
        )?;

        // FIXME(slashing): consider uniqueness and index
        conn.execute(
            "CREATE TABLE signed_attestations (
                validator_id INTEGER,
                source_epoch INTEGER NOT NULL,
                target_epoch INTEGER NOT NULL,
                signing_root BLOB NOT NULL,
                FOREIGN KEY(validator_id) REFERENCES validators(id)
            )",
            params![],
        )?;

        Ok(Self { conn_pool })
    }

    /// Open an existing `SlashingDatabase` from disk.
    pub fn open(path: &Path) -> Result<Self, NotSafe> {
        let manager = SqliteConnectionManager::file(path)
            .with_init(|conn| conn.pragma_update(None, "foreign_keys", &true));
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;
        Ok(Self { conn_pool })
    }

    /// Register a validator with the slashing protection database.
    ///
    /// This allows the validator to record their signatures in the database, and check
    /// for slashings.
    pub fn register_validator(&self, validator_pk: &PublicKey) -> Result<(), NotSafe> {
        let conn = self.conn_pool.get()?;

        conn.execute(
            "INSERT INTO validators (public_key) VALUES (?1)",
            params![validator_pk.as_hex_string()],
        )?;

        Ok(())
    }

    pub fn get_validator_id(
        connection: &PooledConnection<SqliteConnectionManager>,
        public_key: &PublicKey,
    ) -> Result<i64, NotSafe> {
        connection
            .query_row(
                "SELECT id FROM validators WHERE public_key = ?1",
                params![&public_key.as_hex_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| NotSafe::UnregisteredValidator(public_key.clone()))
    }

    pub fn check_block_proposal(
        &self,
        validator_pubkey: &PublicKey,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        let conn = self.conn_pool.get()?;

        // Checking if history is empty
        // FIXME(slashing): check efficacy of these optimisations
        /*
        let mut empty_select = conn.prepare("SELECT 1 FROM signed_blocks LIMIT 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        // Short-circuit: checking if the incoming block has a higher slot than the maximum slot
        // in the DB.
        let mut latest_block_select =
            conn.prepare("SELECT MAX(slot), signing_root FROM signed_blocks")?;
        let latest_block = latest_block_select.query_row(params![], |row| {
            let slot = row.get(0)?;
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(&signing_bytes);
            Ok(SignedBlock::new(slot, signing_root))
        })?;

        if block_header.slot > latest_block.slot {
            return Ok(Safe {
                reason: ValidityReason::Valid,
            });
        }

        // Checking for Pruning Error i.e the incoming block slot is smaller than the minimum slot
        // signed in the DB.
        let mut min_select = conn.prepare("SELECT MIN(slot) FROM signed_blocks")?;
        let oldest_slot: Slot = min_select.query_row(params![], |row| row.get(0))?;
        if block_header.slot < oldest_slot {
            // FIXME(slashing): consider renaming
            return Err(NotSafe::PruningError);
        }
        */

        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        let existing_block_root = conn
            .prepare(
                "SELECT signing_root
                 FROM signed_blocks
                 WHERE validator_id = ?1 AND slot = ?2",
            )?
            .query_row(params![validator_id, block_header.slot], |row| {
                let signing_bytes: Vec<u8> = row.get(0)?;
                Ok(Hash256::from_slice(&signing_bytes))
            })
            .optional()?;

        if let Some(existing_block_root) = existing_block_root {
            if existing_block_root == block_header.canonical_root() {
                // Same slot and same hash -> we're re-broadcasting a previously signed block
                Ok(Safe {
                    reason: ValidityReason::SameData,
                })
            } else {
                // Same epoch but not the same hash -> it's a DoubleBlockProposal
                Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    SignedBlock {
                        slot: block_header.slot,
                        signing_root: existing_block_root,
                    },
                )))
            }
        } else {
            Ok(Safe {
                reason: ValidityReason::Valid,
            })
        }
    }

    pub fn check_attestation(
        &self,
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<Safe, NotSafe> {
        let att_source_epoch = attestation.source.epoch;
        let att_target_epoch = attestation.target.epoch;
        let conn = self.conn_pool.get()?;

        // Checking if history is empty
        /* FIXME necessary?
        let mut empty_select = conn.prepare("SELECT 1 FROM signed_attestations LIMIT 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }
        */

        let validator_id = Self::get_validator_id(&conn, validator_pubkey)?;

        // 1. Check for a double vote. Namely, an existing attestation with the same target epoch,
        //    and a different signing root.
        // TODO: consider checking invariants here (1 attestation with a given target), or have a
        // separate invariant check function
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
                return Ok(Safe {
                    reason: ValidityReason::SameData,
                });
            // Otherwise if the hashes are different, this is a double vote.
            } else {
                return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                    existing_attestation,
                )));
            }
        }

        /*
        // Checking for PruningError (where attestation's target is smaller than the minimum
        // target epoch in db)
        let mut min_select = conn.prepare("SELECT MIN(target_epoch) FROM signed_attestations")?;
        let min_target_epoch: Epoch = min_select.query_row(params![], |row| row.get(0))?;
        if att_target_epoch < min_target_epoch {
            return Err(NotSafe::PruningError);
        }
        */

        // 2. Check that no previous votes are surrounding `attestation`.
        // TODO: simplify this to just return an optional row
        let surrounding_attestations = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND source_epoch < ?2 AND target_epoch > ?3
                 ORDER BY target_epoch DESC",
            )?
            .query_map(
                params![validator_id, att_source_epoch, att_target_epoch],
                |row| {
                    let source = row.get(0)?;
                    let target = row.get(1)?;
                    let signing_root: Vec<u8> = row.get(2)?;
                    Ok(SignedAttestation::new(
                        source,
                        target,
                        Hash256::from_slice(&signing_root[..]),
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(prev) = surrounding_attestations.first().cloned() {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::PrevSurroundsNew { prev },
            ));
        }

        // 3. Check that no previous votes are surrounded by `attestation`.
        let surrounded_attestations = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE validator_id = ?1 AND source_epoch > ?2 AND target_epoch < ?3
                 ORDER BY target_epoch DESC",
            )?
            .query_map(
                params![validator_id, att_source_epoch, att_target_epoch],
                |row| {
                    let source = row.get(0)?;
                    let target = row.get(1)?;
                    let signing_root: Vec<u8> = row.get(2)?;
                    Ok(SignedAttestation::new(
                        source,
                        target,
                        Hash256::from_slice(&signing_root[..]),
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(prev) = surrounded_attestations.first().cloned() {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::NewSurroundsPrev { prev },
            ));
        }

        // Everything has been checked, return Valid
        Ok(Safe {
            reason: ValidityReason::Valid,
        })
    }

    fn insert_block_proposal(
        &self,
        validator_pubkey: &PublicKey,
        block_header: &BeaconBlockHeader,
    ) -> Result<(), NotSafe> {
        let conn = self.conn_pool.get()?;

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
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<(), NotSafe> {
        let conn = self.conn_pool.get()?;

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
    ) -> Result<(), NotSafe> {
        match self.check_block_proposal(validator_pubkey, block_header) {
            Ok(safe) => match safe.reason {
                ValidityReason::SameData => Ok(()),
                _ => self.insert_block_proposal(validator_pubkey, block_header),
            },
            Err(notsafe) => Err(notsafe),
        }
    }

    pub fn check_and_insert_attestation(
        &self,
        validator_pubkey: &PublicKey,
        attestation: &AttestationData,
    ) -> Result<(), NotSafe> {
        match self.check_attestation(validator_pubkey, attestation) {
            Ok(safe) => match safe.reason {
                ValidityReason::SameData => Ok(()),
                _ => self.insert_attestation(validator_pubkey, attestation),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}
