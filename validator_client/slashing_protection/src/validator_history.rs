use crate::signed_attestation::SignedAttestation;
use crate::signed_block::SignedBlock;
use crate::utils::{i64_to_u64, u64_to_i64};
use crate::{NotSafe, Safe, ValidityReason};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OpenFlags};
use std::fs::OpenOptions;
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tree_hash::TreeHash;
use types::{AttestationData, BeaconBlockHeader, Hash256};

type Pool = r2d2::Pool<SqliteConnectionManager>;

/// Struct used for checking if attestations or blockheaders are safe from slashing.
#[derive(Debug)]
pub struct ValidatorHistory<T> {
    // The connection to the database.
    pub conn_pool: Pool,
    slots_per_epoch: Option<u64>,

    // Marker for T
    phantom: PhantomData<T>,
}

impl<T> ValidatorHistory<T> {
    pub fn slots_per_epoch(&self) -> Result<u64, NotSafe> {
        self.slots_per_epoch
            .ok_or_else(|| NotSafe::NoSlotsPerEpochProvided)
    }
}

/// Utility function to check for slashing conditions and inserting new attestations/blocks in the db and in memory.
trait CheckAndInsert<T> {
    type U;

    /// Checks if the incoming_data is safe from slashing
    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe>;
    /// Inserts the incoming_data in th sqlite db and in the in-memory vector.
    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl CheckAndInsert<SignedAttestation> for ValidatorHistory<SignedAttestation> {
    type U = AttestationData;

    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        self.check_for_attester_slashing(incoming_data)
    }

    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let target: u64 = incoming_data.target.epoch.into();
        let source: u64 = incoming_data.source.epoch.into();
        let target = u64_to_i64(target);
        let source = u64_to_i64(source);
        self.conn_pool.get()?.execute(
            "INSERT INTO signed_attestations (target_epoch, source_epoch, signing_root)
        VALUES (?1, ?2, ?3)",
            params![target, source, incoming_data.tree_hash_root()],
        )?;
        Ok(())
    }
}

impl CheckAndInsert<SignedBlock> for ValidatorHistory<SignedBlock> {
    type U = BeaconBlockHeader;

    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        self.check_for_proposer_slashing(incoming_data)
    }

    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let slot: u64 = incoming_data.slot.into();
        let slot = u64_to_i64(slot);
        self.conn_pool.get()?.execute(
            "INSERT INTO signed_blocks (slot, signing_root)
                VALUES (?1, ?2)",
            params![slot, incoming_data.canonical_root().as_bytes()],
        )?;
        Ok(())
    }
}

/// Function to load_data from an sqlite db, and store it as a sorted vector.
trait LoadData<T> {
    fn load_data(conn_pool: &Pool) -> Result<Vec<T>, NotSafe>;
}

impl LoadData<SignedAttestation> for Vec<SignedAttestation> {
    fn load_data(conn_pool: &Pool) -> Result<Vec<SignedAttestation>, NotSafe> {
        let conn = conn_pool.get()?;

        let mut attestation_history_select = conn
                .prepare("select target_epoch, source_epoch, signing_root from signed_attestations order by target_epoch asc")?;
        let history = attestation_history_select.query_map(params![], |row| {
            let target: i64 = row.get(0)?;
            let source: i64 = row.get(1)?;
            let target_epoch = i64_to_u64(target);
            let source_epoch = i64_to_u64(source);
            let hash_blob: Vec<u8> = row.get(2)?;
            let signing_root = Hash256::from_slice(hash_blob.as_ref());

            Ok(SignedAttestation::new(
                source_epoch,
                target_epoch,
                signing_root,
            ))
        })?;

        let mut attestation_history = vec![];
        for attestation in history {
            let attestation = attestation?;
            attestation_history.push(attestation)
        }

        Ok(attestation_history)
    }
}

impl LoadData<SignedBlock> for Vec<SignedBlock> {
    fn load_data(conn_pool: &Pool) -> Result<Vec<SignedBlock>, NotSafe> {
        let slots_per_epoch = get_slots_per_epoch(conn_pool)?;
        let conn = conn_pool.get()?;
        let mut block_history_select = conn
            .prepare("select slot, signing_root from signed_blocks where slot order by slot asc")?;
        let history = block_history_select.query_map(params![], |row| {
            let slot: i64 = row.get(0)?;
            let slot = i64_to_u64(slot);
            let hash_blob: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(hash_blob.as_ref());

            Ok(SignedBlock::new(slot, signing_root, slots_per_epoch))
        })?;

        let mut block_history = vec![];
        for block in history {
            let block = block?;
            block_history.push(block)
        }

        Ok(block_history)
    }
}

fn get_slots_per_epoch(conn_pool: &Pool) -> Result<u64, NotSafe> {
    let conn = conn_pool.get()?;
    // check that the slots_per_epoch table only has one row
    let mut count_select = conn.prepare("select count(*) from slots_per_epoch")?;
    let count = count_select.query_row(params![], |row| {
        let count: i32 = row.get(0)?;
        Ok(count)
    })?;

    if count > 1 {
        return Err(NotSafe::SQLError(format!(
            "Multiple slots_per_epoch stored in db. {} found",
            count
        )));
    }

    // select the slots_per_epoch value
    let mut slot_select = conn.prepare("select slots_per_epoch from slots_per_epoch")?;
    let slots_per_epoch = slot_select.query_row(params![], |row| {
        let i64_slot: i64 = row.get(0)?;
        let u64_slot = i64_to_u64(i64_slot);
        Ok(u64_slot)
    })?;
    Ok(slots_per_epoch)
}

pub trait SlashingProtection<T> {
    type U;

    /// Creates an empty ValidatorHistory, and an associated sqlite database with the name passed in as argument.
    /// Returns an error if the database already exists.
    fn empty(path: &Path, slots_per_epoch: Option<u64>) -> Result<ValidatorHistory<T>, NotSafe>;

    /// Creates a ValidatorHistory<T> by connecting to an existing db file.
    /// Returns an error if file doesn't exist.
    fn open(path: &Path, slots_per_epoch: Option<u64>) -> Result<ValidatorHistory<T>, NotSafe>;

    /// Updates the sqlite db and the in-memory Vec if the incoming_data is safe from slashings.
    /// If incoming_data is not safe, returns the associated error.
    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;

    /// Returns a sorted vector containing all the previously signed Ts (i.e. attestations or blocks)
    fn get_history(&self) -> Result<Vec<T>, NotSafe>;
}

impl SlashingProtection<SignedBlock> for ValidatorHistory<SignedBlock> {
    type U = BeaconBlockHeader;

    fn empty(path: &Path, slots_per_epoch: Option<u64>) -> Result<Self, NotSafe> {
        let slots_per_epoch = slots_per_epoch.ok_or_else(|| NotSafe::NoSlotsPerEpochProvided)?;
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;

        let manager = SqliteConnectionManager::file(path);
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {}", e)))?;

        let conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE signed_blocks (
                slot INTEGER,
                signing_root BLOB
            )",
            params![],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX slot_index
                ON signed_blocks(slot)",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE slots_per_epoch (
                slots_per_epoch INTEGER
            )",
            params![],
        )?;

        conn.execute(
            "INSERT INTO slots_per_epoch (slots_per_epoch)
        VALUES (?1)",
            params![u64_to_i64(slots_per_epoch)],
        )?;

        Ok(Self {
            conn_pool,
            slots_per_epoch: Some(slots_per_epoch),
            phantom: PhantomData,
        })
    }

    fn open(path: &Path, curr_slots_per_epoch: Option<u64>) -> Result<Self, NotSafe> {
        let curr_slots_per_epoch =
            curr_slots_per_epoch.ok_or_else(|| NotSafe::NoSlotsPerEpochProvided)?;
        let manager =
            SqliteConnectionManager::file(path).with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {}", e)))?;
        let conn = conn_pool.get()?;

        // check that the slots_per_epoch table only has one row
        let mut count_select = conn.prepare("select count(*) from slots_per_epoch")?;
        let count = count_select.query_row(params![], |row| {
            let count: i32 = row.get(0)?;
            Ok(count)
        })?;

        if count > 1 {
            return Err(NotSafe::SQLError(format!(
                "Multiple slots_per_epoch stored in db. {} found",
                count
            )));
        }

        // select the slots_per_epoch value
        let mut slot_select = conn.prepare("select slots_per_epoch from slots_per_epoch")?;
        let slots_per_epoch = slot_select.query_row(params![], |row| {
            let i64_slot: i64 = row.get(0)?;
            let u64_slot = i64_to_u64(i64_slot);
            Ok(u64_slot)
        })?;

        // check that the slots_per_epoch provided is the same one as the one stored in db
        if curr_slots_per_epoch != slots_per_epoch {
            return Err(NotSafe::SQLError(format!(
                "Incompatible slots_per_epoch: provided: {}, stored: {}",
                curr_slots_per_epoch, slots_per_epoch
            )));
        }

        Ok(Self {
            conn_pool,
            slots_per_epoch: Some(slots_per_epoch),
            phantom: PhantomData,
        })
    }

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.check_slashing(incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self.insert(incoming_data),
            },
            Err(notsafe) => Err(notsafe),
        }
    }

    fn get_history(&self) -> Result<Vec<SignedBlock>, NotSafe> {
        <Vec<_> as LoadData<SignedBlock>>::load_data(&self.conn_pool)
    }
}

impl SlashingProtection<SignedAttestation> for ValidatorHistory<SignedAttestation> {
    type U = AttestationData;

    fn empty(path: &Path, slots_per_epoch: Option<u64>) -> Result<Self, NotSafe> {
        if slots_per_epoch.is_some() {
            return Err(NotSafe::UnnecessarySlotsPerEpoch);
        }

        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;

        let manager = SqliteConnectionManager::file(path);
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {}", e)))?;

        let conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE signed_attestations (
                target_epoch INTEGER,
                source_epoch INTEGER,
                signing_root BLOB
            )",
            params![],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX target_index
                ON signed_attestations(target_epoch)",
            params![],
        )?;

        conn.execute(
            "CREATE INDEX source_index
                ON signed_attestations(source_epoch)",
            params![],
        )?;

        Ok(Self {
            conn_pool,
            slots_per_epoch,
            phantom: PhantomData,
        })
    }

    fn open(path: &Path, slots_per_epoch: Option<u64>) -> Result<Self, NotSafe> {
        if slots_per_epoch.is_some() {
            return Err(NotSafe::UnnecessarySlotsPerEpoch);
        }

        let manager =
            SqliteConnectionManager::file(path).with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn_pool = Pool::new(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {}", e)))?;

        Ok(Self {
            conn_pool,
            slots_per_epoch,
            phantom: PhantomData,
        })
    }

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.check_slashing(incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self.insert(incoming_data),
            },
            Err(notsafe) => Err(notsafe),
        }
    }

    fn get_history(&self) -> Result<Vec<SignedAttestation>, NotSafe> {
        <Vec<_> as LoadData<SignedAttestation>>::load_data(&self.conn_pool)
    }
}

#[cfg(test)]
mod single_threaded_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::Signature;
    use types::{
        AttestationData, BeaconBlockHeader, Checkpoint, Epoch, EthSpec, Hash256, MinimalEthSpec,
        Slot,
    };

    fn attestation_data_builder(source: u64, target: u64) -> AttestationData {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let slot = Slot::from(0u64);
        let index = 0u64;

        AttestationData {
            slot,
            index,
            beacon_block_root: Hash256::zero(),
            source,
            target,
        }
    }

    fn block_builder(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: Slot::from(slot),
            parent_root: Hash256::random(),
            state_root: Hash256::random(),
            body_root: Hash256::random(),
            signature: Signature::empty_signature(),
        }
    }

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(epoch_num),
            root: Hash256::zero(),
        }
    }

    #[test]
    fn simple_attestation_insertion() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(filename, None).expect("IO error with file");

        let attestation1 = attestation_data_builder(1, 2);
        let attestation2 = attestation_data_builder(2, 3);
        let attestation3 = attestation_data_builder(3, 4);

        let _ = attestation_history.update_if_valid(&attestation1);
        let _ = attestation_history.update_if_valid(&attestation2);
        let _ = attestation_history.update_if_valid(&attestation3);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation2));
        expected_vector.push(SignedAttestation::from(&attestation3));

        assert_eq!(
            expected_vector,
            attestation_history
                .get_history()
                .expect("error with sql db")
        );

        // Copying the current data
        let old_data = attestation_history
            .get_history()
            .expect("error with sql db");

        // Dropping the ValidatorHistory struct
        drop(attestation_history);

        let file_written_version: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::open(filename, None).expect("IO error with file");
        // Making sure that data in the file is correct
        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        attestation_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn open_non_existing_db() {
        let filename = Path::new("this_file_does_not_exist.txt");

        let attestation_history: Result<ValidatorHistory<SignedAttestation>, NotSafe> =
            ValidatorHistory::open(filename, None);

        assert!(attestation_history.is_err()); // SCOTT
    }

    #[test]
    fn open_invalid_db() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let attestation_filename = attestation_file.path();

        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let block_filename = block_file.path();

        let mut attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::open(attestation_filename, None).expect("IO error with file");

        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
        let block_history: Result<ValidatorHistory<SignedBlock>, NotSafe> =
            ValidatorHistory::open(block_filename, Some(slots_per_epoch));

        assert!(block_history.is_err());
        assert_eq!(
            block_history.unwrap_err(),
            NotSafe::SQLError("no such table: slots_per_epoch".to_string())
        );

        let attestation1 = attestation_data_builder(5, 9);
        let invalid_attest = attestation_history.update_if_valid(&attestation1);
        assert_eq!(
            invalid_attest,
            Err(NotSafe::SQLError(
                "no such table: signed_attestations".to_string()
            ))
        );
    }

    #[test]
    fn create_two_empty_attestation_history() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let attestation_filename = attestation_file.path();

        let _: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(attestation_filename, None).expect("IO error with file");

        let attestation_history: Result<ValidatorHistory<SignedAttestation>, NotSafe> =
            ValidatorHistory::empty(attestation_filename, None);

        assert!(
            attestation_history.is_err(),
            "should have resulted in an error"
        );
        assert_eq!(
            attestation_history.unwrap_err(),
            NotSafe::SQLError("table signed_attestations already exists".to_string())
        );
    }

    #[test]
    fn create_two_empty_block_history() {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let block_filename = block_file.path();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let _: ValidatorHistory<SignedBlock> =
            ValidatorHistory::empty(block_filename, Some(slots_per_epoch))
                .expect("IO error with file");

        let block_history: Result<ValidatorHistory<SignedBlock>, NotSafe> =
            ValidatorHistory::empty(block_filename, Some(slots_per_epoch));

        assert!(block_history.is_err(), "should have resulted in an error");
        assert_eq!(
            block_history.unwrap_err(),
            NotSafe::SQLError("table signed_blocks already exists".to_string())
        );
    }

    #[test]
    fn no_slots_per_epoch_provided() {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let block_filename = block_file.path();

        let block_history: Result<ValidatorHistory<SignedBlock>, NotSafe> =
            ValidatorHistory::empty(block_filename, None);

        assert!(block_history.is_err(), "should have resulted in an error");
        assert_eq!(block_history.unwrap_err(), NotSafe::NoSlotsPerEpochProvided);
    }

    #[test]
    fn slots_per_epoch_provided() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let attestation_filename = attestation_file.path();

        let attestation_history: Result<ValidatorHistory<SignedAttestation>, NotSafe> =
            ValidatorHistory::empty(attestation_filename, Some(123));

        assert!(
            attestation_history.is_err(),
            "should have resulted in an error"
        );
        assert_eq!(
            attestation_history.unwrap_err(),
            NotSafe::UnnecessarySlotsPerEpoch
        );
    }

    #[test]
    fn interlaced_attestation_insertion() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(filename, None).expect("IO error with file");

        let attestation1 = attestation_data_builder(5, 9);
        let attestation2 = attestation_data_builder(7, 12);
        let attestation3 = attestation_data_builder(5, 10);
        let attestation4 = attestation_data_builder(6, 11);
        let attestation5 = attestation_data_builder(8, 13);

        let _ = attestation_history.update_if_valid(&attestation1);
        let _ = attestation_history.update_if_valid(&attestation2);
        let _ = attestation_history.update_if_valid(&attestation3);
        let _ = attestation_history.update_if_valid(&attestation4);
        let _ = attestation_history.update_if_valid(&attestation5);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation3));
        expected_vector.push(SignedAttestation::from(&attestation4));
        expected_vector.push(SignedAttestation::from(&attestation2));
        expected_vector.push(SignedAttestation::from(&attestation5));

        // Making sure that data in memory is correct..
        assert_eq!(
            expected_vector,
            attestation_history
                .get_history()
                .expect("error with sql db")
        );

        // Copying the current data
        let old_data = attestation_history
            .get_history()
            .expect("error with sql db");
        // Dropping the ValidatorHistory struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::open(filename, None).expect("IO error with file");
        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        attestation_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn attestation_with_failures() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(filename, None).expect("IO error with file");

        let attestation1 = attestation_data_builder(1, 2);
        let attestation2 = attestation_data_builder(1, 2); // should not get added
        let attestation3 = attestation_data_builder(2, 3);
        let attestation4 = attestation_data_builder(1, 3); // should not get added
        let attestation5 = attestation_data_builder(3, 4);

        let _ = attestation_history.update_if_valid(&attestation1);
        let _ = attestation_history.update_if_valid(&attestation2);
        let _ = attestation_history.update_if_valid(&attestation3);
        let _ = attestation_history.update_if_valid(&attestation4);
        let _ = attestation_history.update_if_valid(&attestation5);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation3));
        expected_vector.push(SignedAttestation::from(&attestation5));

        // Making sure that data in memory is correct..
        assert_eq!(
            expected_vector,
            attestation_history
                .get_history()
                .expect("error with sql db")
        );

        // Copying the current data
        let old_data = attestation_history
            .get_history()
            .expect("error with sql db");
        // Dropping the ValidatorHistory struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::open(filename, None).expect("IO error with file");
        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        attestation_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn loading_from_file() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(filename, None).expect("IO error with file");

        let attestation1 = attestation_data_builder(1, 2);
        let attestation2 = attestation_data_builder(2, 3);
        let attestation3 = attestation_data_builder(3, 4);

        let a = attestation_history.update_if_valid(&attestation1);
        println!("{:?}", a);
        let b = attestation_history.update_if_valid(&attestation2);
        println!("{:?}", b);
        let c = attestation_history.update_if_valid(&attestation3);
        println!("{:?}", c);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation2));
        expected_vector.push(SignedAttestation::from(&attestation3));

        // Making sure that data in memory is correct..
        assert_eq!(
            expected_vector,
            attestation_history
                .get_history()
                .expect("error with sql db")
        );

        // Copying the current data
        let old_data = attestation_history
            .get_history()
            .expect("error with sql db");
        // Dropping the ValidatorHistory struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let mut file_written_version: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::open(filename, None).expect("IO error with file");

        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        // Inserting new attestations
        let attestation4 = attestation_data_builder(4, 5);
        let attestation5 = attestation_data_builder(5, 6);
        let attestation6 = attestation_data_builder(6, 7);

        let _ = file_written_version.update_if_valid(&attestation4);
        let _ = file_written_version.update_if_valid(&attestation5);
        let _ = file_written_version.update_if_valid(&attestation6);

        expected_vector.push(SignedAttestation::from(&attestation4));
        expected_vector.push(SignedAttestation::from(&attestation5));
        expected_vector.push(SignedAttestation::from(&attestation6));

        assert_eq!(
            expected_vector,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );
        drop(file_written_version);

        attestation_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn simple_block_test() {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = block_file.path();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let mut block_history: ValidatorHistory<SignedBlock> =
            ValidatorHistory::empty(filename, Some(slots_per_epoch)).expect("IO error with file");

        let block1 = block_builder(slots_per_epoch);
        let block2 = block_builder(2 * slots_per_epoch);
        let block3 = block_builder(3 * slots_per_epoch);

        let _ = block_history.update_if_valid(&block1);
        let _ = block_history.update_if_valid(&block2);
        let _ = block_history.update_if_valid(&block3);

        let mut expected_vector = vec![];
        expected_vector.push(SignedBlock::from(&block1, slots_per_epoch));
        expected_vector.push(SignedBlock::from(&block2, slots_per_epoch));
        expected_vector.push(SignedBlock::from(&block3, slots_per_epoch));

        // Making sure that data in memory is correct.
        assert_eq!(
            expected_vector,
            block_history.get_history().expect("error with sql db")
        );

        // Copying the current data
        let old_data = block_history.get_history().expect("error with sql db");
        // Dropping the ValidatorHistory struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: ValidatorHistory<SignedBlock> =
            ValidatorHistory::open(filename, Some(slots_per_epoch)).expect("IO error with file");
        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        block_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn block_with_failures() {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = block_file.path();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let mut block_history: ValidatorHistory<SignedBlock> =
            ValidatorHistory::empty(filename, Some(slots_per_epoch)).expect("IO error with file");

        let block1 = block_builder(slots_per_epoch);
        let block2 = block_builder(slots_per_epoch); // fails
        let block3 = block_builder(2 * slots_per_epoch);
        let block4 = block_builder(2 * slots_per_epoch + 1); // fails
        let block5 = block_builder(10 * slots_per_epoch);
        let block6 = block_builder(0); // fails

        let _ = block_history.update_if_valid(&block1);
        let _ = block_history.update_if_valid(&block2);
        let _ = block_history.update_if_valid(&block3);
        let _ = block_history.update_if_valid(&block4);
        let _ = block_history.update_if_valid(&block5);
        let _ = block_history.update_if_valid(&block6);

        let mut expected_vector = vec![];
        expected_vector.push(SignedBlock::from(&block1, slots_per_epoch));
        expected_vector.push(SignedBlock::from(&block3, slots_per_epoch));
        expected_vector.push(SignedBlock::from(&block5, slots_per_epoch));

        // Making sure that data in memory is correct.
        assert_eq!(
            expected_vector,
            block_history.get_history().expect("error with sql db"),
            "data in memory is incorrect"
        );

        // Copying the current data
        let old_data = block_history.get_history().expect("error with sql db");
        // Dropping the ValidatorHistory struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: ValidatorHistory<SignedBlock> =
            ValidatorHistory::open(filename, Some(slots_per_epoch)).expect("IO error with file");
        assert_eq!(
            old_data,
            file_written_version
                .get_history()
                .expect("error with sql db")
        );

        block_file
            .close()
            .expect("temporary file not properly removed");
    }
}
