use crate::attester_slashings::{check_for_attester_slashing, SignedAttestation};
use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::proposer_slashings::{check_for_proposer_slashing, SignedBlock};
use fs2::FileExt;
use ssz::{Decode, Encode};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{ErrorKind, Read, Result as IOResult, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use types::{AttestationData, BeaconBlockHeader};

/// Trait used to know if type T can be checked for slashing safety
pub trait SafeFromSlashing<T> {
    type U;

    /// Verifies that the incoming_data is not slashable and returns
    /// the index at which it should get inserted in the history.
    fn verify_and_get_index(
        &self,
        incoming_data: &Self::U,
        data_history: &[T],
    ) -> Result<Safe, NotSafe>;

    /// Checks if incoming_data is free from slashings, and if so updates the in-memory and writes it to the history file.
    /// If the error returned is an IOError, do not sign nor broadcast the attestation.
    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl SafeFromSlashing<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationData;

    fn verify_and_get_index(
        &self,
        incoming_data: &AttestationData,
        data_history: &[SignedAttestation],
    ) -> Result<Safe, NotSafe> {
        check_for_attester_slashing(incoming_data, data_history)
    }

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.verify_and_get_index(incoming_data, &self.data[..]);
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

    fn verify_and_get_index(
        &self,
        incoming_data: &BeaconBlockHeader,
        data_history: &[SignedBlock],
    ) -> Result<Safe, NotSafe> {
        check_for_proposer_slashing(incoming_data, data_history)
    }

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.verify_and_get_index(incoming_data, &self.data[..]);
        match check {
            Ok(safe) => match safe.reason {
                // Casting the same vote, no need to add it go the history
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

/// Struct used for checking if attestations or blockheader are safe from slashing.
#[derive(Debug, PartialEq)]
pub struct HistoryInfo<T: Encode + Decode + Clone> {
    filepath: PathBuf,
    data: Vec<T>,
}

// impl<T> PartialEq for HistoryInfo<T> {
    // fn eq(&self, other: &Self) -> bool {
        // let my_data = &self.data;
        // let other_data = &other.data;
        // self.filepath == other.filepath && *my_data == *other_data
    // }
// }

impl<T: Encode + Decode + Clone> HistoryInfo<T> {
    /// Inserts the incoming data in the in-memory history, and writes it to the history file.
    pub fn insert_and_write(&mut self, data: T, index: usize) -> IOResult<()> {
        self.data.insert(index, data);

        // Creating file if it doesn't exist, else opening it.
        let mut file = File::create(self.filepath.as_path())?;

        // Locking the file to make sure we're atomically writing to it
        file.lock_exclusive()?;

        // Setting permissions to be 600 (rw-------).
        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;

        // Writing new history to file
        file.write_all(&self.data.as_ssz_bytes())?;

        // Unlocking file because we're done with it.
        file.unlock()?;

        Ok(())
    }
}

impl<T: Encode + Decode + Clone + PartialEq> TryFrom<PathBuf> for HistoryInfo<T> {
    type Error = NotSafe;

    fn try_from(filepath: PathBuf) -> Result<Self, Self::Error> {
        let path = filepath.as_path();
        Self::try_from(path)
    }
}

impl<T: Encode + Decode + Clone + PartialEq> TryFrom<&Path> for HistoryInfo<T> {
    type Error = NotSafe;

    fn try_from(filepath: &Path) -> Result<Self, Self::Error> {
        let mut file = match File::open(filepath) {
            Ok(file) => file,
            Err(e) => match e.kind() {
                // File was not found meaning it has not been created yet, and that history is empty.
                ErrorKind::NotFound => {
                    return Ok(Self {
                        filepath: PathBuf::from(filepath),
                        data: vec![],
                    });
                }
                // Another error occured, report it and stop everything.
                _ => return Err(NotSafe::from(e)),
            },
        };

        // Locking file before reading
        file.lock_exclusive()?;

        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;

        // Unlocking file now that we don't need it anymore
        file.unlock()?;

        let data_history = Vec::from_ssz_bytes(&bytes)?;

        Ok(Self {
            filepath: PathBuf::from(filepath),
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
        let attestation_file = NamedTempFile::new().unwrap();
        let filename = attestation_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");

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

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");
        assert_eq!(attestation_history, file_written_version);

        attestation_file.close().unwrap();
    }

    #[test]
    fn interlaced_attestation_insertion() {
        let attestation_file = NamedTempFile::new().unwrap();
        let filename = attestation_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");

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

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");
        assert_eq!(attestation_history, file_written_version);

        attestation_file.close().unwrap();
    }

    #[test]
    fn attestation_with_failures() {
        let attestation_file = NamedTempFile::new().unwrap();
        let filename = attestation_file.path();

        let mut attestation_history: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");

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

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedAttestation> =
            HistoryInfo::try_from(filename).expect("IO error with file");
        assert_eq!(attestation_history, file_written_version);

        attestation_file.close().unwrap();
    }

    #[test]
    fn simple_block_test() {
        let block_file = NamedTempFile::new().unwrap();
        let filename = block_file.path();

        let mut block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::try_from(filename).expect("IO error with file");

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

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::try_from(filename).expect("IO error with file");
        assert_eq!(block_history, file_written_version);

        block_file.close().unwrap();
    }

    #[test]
    fn block_with_failures() {
        let block_file = NamedTempFile::new().unwrap();
        let filename = block_file.path();

        let mut block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::try_from(filename).expect("IO error with file");

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

        // Making sure that data in the file is correct
        let file_written_version: HistoryInfo<SignedBlock> =
            HistoryInfo::try_from(filename).expect("IO error with file");
        assert_eq!(block_history, file_written_version);

        block_file.close().unwrap();
    }
}
