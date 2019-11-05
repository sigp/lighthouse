use crate::attester_slashings::{check_for_attester_slashing, SignedAttestation};
use crate::enums::{NotSafe, ValidityReason};
use crate::proposer_slashings::{check_for_proposer_slashing, SignedBlock};
use fs2::FileExt;
use ssz::{Decode, Encode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Result as IOResult, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use types::{AttestationData, BeaconBlockHeader};

/// Trait used to know if type T can be checked for slashing safety
pub trait SafeFromSlashing<T> {
    type U;

    /// Checks if incoming_data is free from slashings, and if so updates the in-memory and writes it to the history file.
    /// If the error returned is an IOError, do not sign nor broadcast the attestation.
    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl SafeFromSlashing<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = check_for_attester_slashing(incoming_data, &self.data[..]);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self
                    .insert_and_write(SignedAttestation::from(incoming_data), safe.insert_index)
                    .map_err(|e| NotSafe::IOError(e.kind())),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}

impl SafeFromSlashing<SignedBlock> for HistoryInfo<SignedBlock> {
    type U = BeaconBlockHeader;

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = check_for_proposer_slashing(incoming_data, &self.data[..]);
        match check {
            Ok(safe) => match safe.reason {
                // Casting the same vote, no need to add it to the history
                ValidityReason::SameVote => Ok(()),
                // New attestation, add it to memory and file history
                _ => self
                    .insert_and_write(SignedBlock::from(incoming_data), safe.insert_index)
                    .map_err(|e| NotSafe::IOError(e.kind())),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}

/// Struct used for checking if attestations or blockheaders are safe from slashing.
#[derive(Debug)]
pub struct HistoryInfo<T> {
    file: File,
    data: Vec<T>,
}

impl<T: Clone + Encode + Decode> HistoryInfo<T> {
    /// Inserts the incoming data in the in-memory history, and writes it to the history file.
    fn insert_and_write(&mut self, data: T, index: usize) -> IOResult<()> {
        // Insert the incoming data in memory
        self.data.insert(index, data);

        // Writing new history to file
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.data.as_ssz_bytes())?;

        Ok(())
    }

    pub fn empty(path: &Path) -> Result<Self, NotSafe> {
        let file = File::create(path)?;

        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;
        Self::open(path)
    }

    pub fn open(path: &Path) -> Result<Self, NotSafe> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        file.try_lock_exclusive()?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;

        let data_history = Vec::from_ssz_bytes(&bytes)?;

        Ok(Self {
            file,
            data: data_history.to_vec(),
        })
    }
}

#[cfg(test)]
mod single_threaded_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::{AttestationData, Checkpoint, Crosslink, Epoch, Hash256, Signature, Slot};

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
