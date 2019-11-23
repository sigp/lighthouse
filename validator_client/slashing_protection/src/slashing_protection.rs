use crate::attester_slashings::SignedAttestation;
use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::proposer_slashings::SignedBlock;
use crate::utils::{i64_to_u64, u64_to_i64};
use rusqlite::{params, Connection, Error as SQLErr, OpenFlags};
use std::fs::OpenOptions;
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tree_hash::TreeHash;
use types::{AttestationData, BeaconBlockHeader, Hash256};

/// Struct used for checking if attestations or blockheaders are safe from slashing.
#[derive(Debug)]
pub struct HistoryInfo<T> {
    // The connection to the database.
    pub conn: Connection,

    // Marker for T
    phantom: PhantomData<T>,
}

/// Utility function to check for slashing conditions and inserting new attestations/blocks in the db and in memory.
trait CheckAndInsert<T> {
    type U;

    /// Checks if the incoming_data is safe from slashing
    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe>;
    /// Inserts the incoming_data in th sqlite db and in the in-memory vector.
    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl CheckAndInsert<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        self.check_for_attester_slashing(incoming_data)
    }

    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let target: u64 = incoming_data.target.epoch.into();
        let source: u64 = incoming_data.source.epoch.into();
        let target = u64_to_i64(target);
        let source = u64_to_i64(source);
        self.conn.execute(
            "INSERT INTO signed_attestations (target_epoch, source_epoch, signing_root)
        VALUES (?1, ?2, ?3)",
            params![target, source, incoming_data.tree_hash_root()],
        )?;
        Ok(())
    }
}

impl CheckAndInsert<SignedBlock> for HistoryInfo<SignedBlock> {
    type U = BeaconBlockHeader;

    fn check_slashing(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        self.check_for_proposer_slashing(incoming_data) // SCOTT
    }

    fn insert(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let slot: u64 = incoming_data.slot.into();
        let slot = u64_to_i64(slot);
        self.conn.execute(
            "INSERT INTO signed_blocks (slot, signing_root)
                VALUES (?1, ?2)",
            params![slot, incoming_data.canonical_root().as_bytes()],
        )?;
        Ok(())
    }
}

/// Function to load_data from an sqlite db, and store it as a sorted vector.
trait LoadData<T> {
    fn load_data(conn: &Connection) -> Result<Vec<T>, SQLErr>;
}

impl LoadData<SignedAttestation> for Vec<SignedAttestation> {
    fn load_data(conn: &Connection) -> Result<Vec<SignedAttestation>, SQLErr> {
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
    fn load_data(conn: &Connection) -> Result<Vec<SignedBlock>, SQLErr> {
        let mut block_history_select = conn
            .prepare("select slot, signing_root from signed_blocks where slot order by slot asc")?;
        let history = block_history_select.query_map(params![], |row| {
            let slot: i64 = row.get(0)?;
            let slot = i64_to_u64(slot);
            let hash_blob: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(hash_blob.as_ref());

            Ok(SignedBlock::new(slot, signing_root))
        })?;

        let mut block_history = vec![];
        for block in history {
            let block = block?;
            block_history.push(block)
        }

        Ok(block_history)
    }
}

pub trait SlashingProtection<T> {
    type U;

    /// Creates an empty HistoryInfo, and an associated sqlite database with the name passed in as argument.
    /// Returns an error if the database already exists.
    fn empty(path: &Path) -> Result<HistoryInfo<T>, NotSafe>;

    /// Creates a HistoryInfo<T> by connecting to an existing db file.
    /// Returns an error if file doesn't exist.
    fn open(path: &Path) -> Result<HistoryInfo<T>, NotSafe>;

    /// Updates the sqlite db and the in-memory Vec if the incoming_data is safe from slashings.
    /// If incoming_data is not safe, returns the associated error.
    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;

    /// Returns a sorted vector containing all the previously signed Ts (i.e. attestations or blocks)
    fn get_history(&self) -> Result<Vec<T>, SQLErr>;
}

impl SlashingProtection<SignedBlock> for HistoryInfo<SignedBlock> {
    type U = BeaconBlockHeader;

    fn empty(path: &Path) -> Result<Self, NotSafe> {
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS signed_blocks (
                slot INTEGER,
                signing_root BLOB
            )",
            params![],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS slot_index
                ON signed_blocks(slot)",
            params![],
        )?;

        Ok(Self {
            conn,
            phantom: PhantomData,
        })
    }

    fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

        Ok(Self {
            conn,
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

    fn get_history(&self) -> Result<Vec<SignedBlock>, SQLErr> {
        <Vec<_> as LoadData<SignedBlock>>::load_data(&self.conn)
    }
}

impl SlashingProtection<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn empty(path: &Path) -> Result<Self, NotSafe> {
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS signed_attestations (
                target_epoch INTEGER,
                source_epoch INTEGER,
                signing_root BLOB
            )",
            params![],
        )?;

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS target_index
                ON signed_attestations(target_epoch)",
            params![],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS source_index
                ON signed_attestations(source_epoch)",
            params![],
        )?;

        Ok(Self {
            conn,
            phantom: PhantomData,
        })
    }

    fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

        Ok(Self {
            conn,
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

    fn get_history(&self) -> Result<Vec<SignedAttestation>, SQLErr> {
        <Vec<_> as LoadData<SignedAttestation>>::load_data(&self.conn)
    }
}

#[cfg(test)]
mod single_threaded_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::{AttestationData, BeaconBlockHeader, Checkpoint, Epoch, Hash256, Slot};
    use types::{Signature};

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

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::empty(filename).expect("IO error with file");

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

        // Dropping the HistoryInfo struct
        drop(attestation_history);

        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
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

        let attestation_history: Result<HistoryInfo<SignedAttestation>, NotSafe> =
            HistoryInfo::open(filename);

        assert!(attestation_history.is_err()); // SCOTT
    }

    #[test]
    fn open_invalid_db() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let attestation_filename = attestation_file.path();

        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let block_filename = block_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(attestation_filename).expect("IO error with file");

        let mut block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::open(block_filename).expect("IO error with file");

        let attestation1 = attestation_data_builder(5, 9);
        let invalid_attest = attestation_history.update_if_valid(&attestation1);
        assert_eq!(
            invalid_attest,
            Err(NotSafe::SQLError(
                "no such table: signed_attestations".to_string()
            ))
        ); // SCOTT

        let block1 = block_builder(1);
        let invalid_block = block_history.update_if_valid(&block1);
        assert_eq!(
            invalid_block,
            Err(NotSafe::SQLError(
                "no such table: signed_blocks".to_string()
            ))
        ); // SCOTT
    }

    #[test]
    fn interlaced_attestation_insertion() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::empty(filename).expect("IO error with file");

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
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
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

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::empty(filename).expect("IO error with file");

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
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
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

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::empty(filename).expect("IO error with file");

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
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let mut file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");

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

        let mut block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::empty(filename).expect("IO error with file");

        let block1 = block_builder(1);
        let block2 = block_builder(2);
        let block3 = block_builder(3);

        let _ = block_history.update_if_valid(&block1);
        let _ = block_history.update_if_valid(&block2);
        let _ = block_history.update_if_valid(&block3);

        let mut expected_vector = vec![];
        expected_vector.push(SignedBlock::from(&block1));
        expected_vector.push(SignedBlock::from(&block2));
        expected_vector.push(SignedBlock::from(&block3));

        // Making sure that data in memory is correct.
        assert_eq!(
            expected_vector,
            block_history.get_history().expect("error with sql db")
        );

        // Copying the current data
        let old_data = block_history.get_history().expect("error with sql db");
        // Dropping the HistoryInfo struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::open(filename).expect("IO error with file");
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

        let mut block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::empty(filename).expect("IO error with file");

        let block1 = block_builder(1);
        let block2 = block_builder(1); // fails
        let block3 = block_builder(2);
        let block4 = block_builder(10);
        let block5 = block_builder(0); // fails

        let _ = block_history.update_if_valid(&block1);
        let _ = block_history.update_if_valid(&block2);
        let _ = block_history.update_if_valid(&block3);
        let _ = block_history.update_if_valid(&block4);
        let _ = block_history.update_if_valid(&block5);

        let mut expected_vector = vec![];
        expected_vector.push(SignedBlock::from(&block1));
        expected_vector.push(SignedBlock::from(&block3));
        expected_vector.push(SignedBlock::from(&block4));

        // Making sure that data in memory is correct.
        assert_eq!(
            expected_vector,
            block_history.get_history().expect("error with sql db")
        );

        // Copying the current data
        let old_data = block_history.get_history().expect("error with sql db");
        // Dropping the HistoryInfo struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::open(filename).expect("IO error with file");
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
