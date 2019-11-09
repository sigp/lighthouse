use crate::attester_slashings::{check_for_attester_slashing, SignedAttestation};
use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::proposer_slashings::{check_for_proposer_slashing, SignedBlock};
use rusqlite::{params, Connection};
use ssz::Decode;
use ssz::Encode;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tree_hash::TreeHash;
use types::{AttestationData, BeaconBlockHeader, Hash256}; // dump data // for dump data

/// Struct used for checking if attestations or blockheaders are safe from slashing.
#[derive(Debug)]
pub struct HistoryInfo<T> {
    conn: Connection,
    pub data: Vec<T>,
}

/// Trait used to know if type T can be checked for slashing safety
pub trait SafeFromSlashing<T> {
    type U;

    /// Checks if incoming_data is free from slashings, and if so updates the in-memory and writes it to the history file.
    /// If the error returned is an IOError, do not sign nor broadcast the attestation.
    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

trait CheckAndInsert<T> {
    type U;

    fn check(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe>;
    fn insert(&mut self, insert_index: usize, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl CheckAndInsert<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn check(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        check_for_attester_slashing(incoming_data, &self.data[..])
    }

    fn insert(&mut self, insert_index: usize, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let target: u64 = incoming_data.target.epoch.into();
        let source: u64 = incoming_data.source.epoch.into();
        self.conn.execute(
            "INSERT INTO signed_attestations (target_epoch, source_epoch, signing_root)
        VALUES (?1, ?2, ?3)",
            params![
                target as i64,
                source as i64,
                Hash256::from_slice(&incoming_data.tree_hash_root()).as_ssz_bytes()
            ],
        )?;
        self.data
            .insert(insert_index, SignedAttestation::from(incoming_data));
        Ok(())
    }
}

impl CheckAndInsert<SignedBlock> for HistoryInfo<SignedBlock> {
    type U = BeaconBlockHeader;

    fn check(&self, incoming_data: &Self::U) -> Result<Safe, NotSafe> {
        check_for_proposer_slashing(incoming_data, &self.data[..])
    }

    fn insert(&mut self, insert_index: usize, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let slot: u64 = incoming_data.slot.into();
        self.conn.execute(
            "INSERT INTO signed_blocks (slot, signing_root)
                VALUES (?1, ?2)",
            params![slot as i64, incoming_data.canonical_root().as_ssz_bytes()],
        )?;
        self.data
            .insert(insert_index, SignedBlock::from(incoming_data));
        Ok(())
    }
}

trait LoadData<T> {
    fn load_data(conn: &Connection) -> Vec<T>;
}

impl LoadData<SignedAttestation> for Vec<SignedAttestation> {
    fn load_data(conn: &Connection) -> Vec<SignedAttestation> {
        let mut attestation_history_select = conn
                .prepare("select target_epoch, source_epoch, signing_root from signed_attestations order by target_epoch asc")
                .unwrap();
        let history = attestation_history_select
            .query_map(params![], |row| {
                let target_i: i64 = row.get(0).unwrap();
                let source_i: i64 = row.get(1).unwrap();
                let target_epoch = target_i as u64;
                let source_epoch = source_i as u64;
                let hash_blob: Vec<u8> = row.get(2).unwrap();
                let signing_root = Hash256::from_ssz_bytes(hash_blob.as_ref())
                    .expect("should have a valid ssz encoded hash256 in db");

                Ok(SignedAttestation::new(
                    source_epoch,
                    target_epoch,
                    signing_root,
                ))
            })
            .unwrap();

        let mut attestation_history = vec![];
        for attestation in history {
            attestation_history.push(attestation.unwrap())
        }

        attestation_history.sort_by(|a, b| a.target_epoch.partial_cmp(&b.target_epoch).unwrap());
        attestation_history
    }
}

impl LoadData<SignedBlock> for Vec<SignedBlock> {
    fn load_data(conn: &Connection) -> Vec<SignedBlock> {
        let mut block_history_select = conn
            .prepare("select slot, signing_root from signed_blocks where slot order by slot asc")
            .unwrap();
        let history = block_history_select
            .query_map(params![], |row| {
                let slot_i: i64 = row.get(0).unwrap();
                let slot = slot_i as u64;
                let hash_blob: Vec<u8> = row.get(1).unwrap();
                let signing_root = Hash256::from_ssz_bytes(hash_blob.as_ref())
                    .expect("should have a valid ssz encoded hash256 in db");

                Ok(SignedBlock::new(slot, signing_root))
            })
            .unwrap();

        let mut block_history = vec![];
        for block in history {
            block_history.push(block.unwrap())
        }

        block_history.sort_by(|a, b| a.slot.partial_cmp(&b.slot).unwrap());
        block_history
    }
}

impl SafeFromSlashing<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.check(incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self.insert(safe.insert_index, incoming_data),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}

impl SafeFromSlashing<SignedBlock> for HistoryInfo<SignedBlock> {
    type U = BeaconBlockHeader;

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.check(incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self.insert(safe.insert_index, incoming_data),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}

trait OpenOrEmpty<T> {
    fn empty(path: &Path) -> Result<HistoryInfo<T>, NotSafe>; // should not be NotSafe.. ?
    fn open(path: &Path) -> Result<HistoryInfo<T>, NotSafe>;
}

impl OpenOrEmpty<SignedBlock> for HistoryInfo<SignedBlock> {
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
            data: Vec::new(),
        })
    }

    fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn = Connection::open(path)?;

        let data = <Vec<_> as LoadData<SignedBlock>>::load_data(&conn);

        Ok(Self { conn, data })
    }
}

impl OpenOrEmpty<SignedAttestation> for HistoryInfo<SignedAttestation> {
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

        Ok(Self {
            conn,
            data: Vec::new(),
        })
    }

    fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn = Connection::open(path)?;

        let data = <Vec<_> as LoadData<SignedAttestation>>::load_data(&conn);

        Ok(Self { conn, data })
    }
}

#[cfg(test)]
mod single_threaded_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::{AttestationData, BeaconBlockHeader, Epoch, Hash256, Slot};
    use types::{Checkpoint, Crosslink, Signature};

    fn attestation_and_custody_bit_builder(source: u64, target: u64) -> AttestationData {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let crosslink = Crosslink::default();

        AttestationData {
            beacon_block_root: Hash256::zero(),
            source,
            target,
            crosslink,
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

        let attestation1 = attestation_and_custody_bit_builder(1, 2);
        let attestation2 = attestation_and_custody_bit_builder(2, 3);
        let attestation3 = attestation_and_custody_bit_builder(3, 4);

        let _ = attestation_history.update_if_valid(&attestation1);
        let _ = attestation_history.update_if_valid(&attestation2);
        let _ = attestation_history.update_if_valid(&attestation3);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation2));
        expected_vector.push(SignedAttestation::from(&attestation3));

        assert_eq!(expected_vector, attestation_history.data);

        // Copying the current data
        let old_data = attestation_history.data.clone();

        // Dropping the HistoryInfo struct
        drop(attestation_history);

        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
        // Making sure that data in the file is correct
        assert_eq!(old_data, file_written_version.data);

        attestation_file
            .close()
            .expect("temporary file not properly removed");
    }

    #[test]
    fn interlaced_attestation_insertion() {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::empty(filename).expect("IO error with file");

        let attestation1 = attestation_and_custody_bit_builder(5, 9);
        let attestation2 = attestation_and_custody_bit_builder(7, 12);
        let attestation3 = attestation_and_custody_bit_builder(5, 10);
        let attestation4 = attestation_and_custody_bit_builder(6, 11);
        let attestation5 = attestation_and_custody_bit_builder(8, 13);

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
        assert_eq!(expected_vector, attestation_history.data);

        // Copying the current data
        let old_data = attestation_history.data.clone();
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
        assert_eq!(old_data, file_written_version.data);

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

        let attestation1 = attestation_and_custody_bit_builder(1, 2);
        let attestation2 = attestation_and_custody_bit_builder(1, 2); // should not get added
        let attestation3 = attestation_and_custody_bit_builder(2, 3);
        let attestation4 = attestation_and_custody_bit_builder(1, 3); // should not get added
        let attestation5 = attestation_and_custody_bit_builder(3, 4);

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
        assert_eq!(expected_vector, attestation_history.data);

        // Copying the current data
        let old_data = attestation_history.data.clone();
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");
        assert_eq!(old_data, file_written_version.data);

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

        let attestation1 = attestation_and_custody_bit_builder(1, 2);
        let attestation2 = attestation_and_custody_bit_builder(2, 3);
        let attestation3 = attestation_and_custody_bit_builder(3, 4);

        let _ = attestation_history.update_if_valid(&attestation1);
        let _ = attestation_history.update_if_valid(&attestation2);
        let _ = attestation_history.update_if_valid(&attestation3);

        let mut expected_vector = vec![];
        expected_vector.push(SignedAttestation::from(&attestation1));
        expected_vector.push(SignedAttestation::from(&attestation2));
        expected_vector.push(SignedAttestation::from(&attestation3));

        // Making sure that data in memory is correct..
        assert_eq!(expected_vector, attestation_history.data);

        // Copying the current data
        let old_data = attestation_history.data.clone();
        // Dropping the HistoryInfo struct
        drop(attestation_history);

        // Making sure that data in the file is correct
        let mut file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::open(filename).expect("IO error with file");

        assert_eq!(old_data, file_written_version.data);

        // Inserting new attestations
        let attestation4 = attestation_and_custody_bit_builder(4, 5);
        let attestation5 = attestation_and_custody_bit_builder(5, 6);
        let attestation6 = attestation_and_custody_bit_builder(6, 7);

        let _ = file_written_version.update_if_valid(&attestation4);
        let _ = file_written_version.update_if_valid(&attestation5);
        let _ = file_written_version.update_if_valid(&attestation6);

        expected_vector.push(SignedAttestation::from(&attestation4));
        expected_vector.push(SignedAttestation::from(&attestation5));
        expected_vector.push(SignedAttestation::from(&attestation6));

        assert_eq!(expected_vector, file_written_version.data);
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
        assert_eq!(expected_vector, block_history.data);

        // Copying the current data
        let old_data = block_history.data.clone();
        // Dropping the HistoryInfo struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::open(filename).expect("IO error with file");
        assert_eq!(old_data, file_written_version.data);

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

        let a = block_history.update_if_valid(&block1);
        println!("{:?}", a);
        let b = block_history.update_if_valid(&block2);
        println!("{:?}", b);
        let c = block_history.update_if_valid(&block3);
        println!("{:?}", c);
        let d = block_history.update_if_valid(&block4);
        println!("{:?}", d);
        let e = block_history.update_if_valid(&block5);
        println!("{:?}", e);

        let mut expected_vector = vec![];
        expected_vector.push(SignedBlock::from(&block1));
        expected_vector.push(SignedBlock::from(&block3));
        expected_vector.push(SignedBlock::from(&block4));

        // Making sure that data in memory is correct.
        assert_eq!(expected_vector, block_history.data);

        // Copying the current data
        let old_data = block_history.data.clone();
        // Dropping the HistoryInfo struct
        drop(block_history);

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::open(filename).expect("IO error with file");
        assert_eq!(old_data, file_written_version.data);

        block_file
            .close()
            .expect("temporary file not properly removed");
    }
}
