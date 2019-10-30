use crate::attester_slashings::{check_for_attester_slashing, SignedAttestation};
use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::proposer_slashings::{check_for_proposer_slashing, SignedBlock};
use fs2::FileExt;
use ssz::{Decode, Encode};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read, Result as IOResult, Write};
use std::path::{Path, PathBuf};
use types::{AttestationDataAndCustodyBit, BeaconBlockHeader};

/// Trait used to know if type T can be checked for slashing safety
trait SafeFromSlashing<T> {
    type U;

    /// Verifies that the incoming_data is not slashable and returns
    /// the index at which it should get inserted in the history.
    fn verify_and_get_index(
        &self,
        incoming_data: &Self::U,
        data_history: &[T],
    ) -> Result<Safe, NotSafe>;

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe>;
}

impl SafeFromSlashing<SignedAttestation> for HistoryInfo<SignedAttestation> {
    type U = AttestationDataAndCustodyBit;

    fn verify_and_get_index(
        &self,
        incoming_data: &AttestationDataAndCustodyBit,
        data_history: &[SignedAttestation],
    ) -> Result<Safe, NotSafe> {
        check_for_attester_slashing(incoming_data, data_history)
    }

    fn update_if_valid(&mut self, incoming_data: &Self::U) -> Result<(), NotSafe> {
        let check = self.check_for_slashing(&incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self
                    .update_and_write(SignedAttestation::from(incoming_data), safe.insert_index)
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
        let check = self.check_for_slashing(&incoming_data);
        match check {
            Ok(safe) => match safe.reason {
                ValidityReason::SameVote => Ok(()),
                _ => self
                    .update_and_write(SignedBlock::from(incoming_data), safe.insert_index)
                    .map_err(|e| NotSafe::IOError(e.kind())),
            },
            Err(notsafe) => Err(notsafe),
        }
    }
}

#[derive(Debug)]
struct HistoryInfo<T: Encode + Decode + Clone + PartialEq> {
    filepath: PathBuf,
    data: Vec<T>,
}

impl<T: Encode + Decode + Clone + PartialEq> PartialEq for HistoryInfo<T> {
    fn eq(&self, other: &Self) -> bool {
        let my_data = &self.data;
        let other_data = &other.data;
        self.filepath == other.filepath && *my_data == *other_data
    }
}

impl<T: Encode + Decode + Clone + PartialEq> HistoryInfo<T> {
    pub fn update_and_write(&mut self, data: T, index: usize) -> IOResult<()> {
        self.data.insert(index, data);
        let mut file = File::create(self.filepath.as_path()).unwrap();
        file.lock_exclusive()?;
        file.write_all(&self.data.as_ssz_bytes())?;
        file.unlock()?;

        Ok(())
    }

    fn check_for_slashing(
        &self,
        incoming_data: &<HistoryInfo<T> as SafeFromSlashing<T>>::U,
    ) -> Result<Safe, NotSafe>
    where
        Self: SafeFromSlashing<T>,
    {
        let data_history = &self.data[..];
        self.verify_and_get_index(incoming_data, data_history)
    }
}

impl<T: Encode + Decode + Clone + PartialEq> TryFrom<&Path> for HistoryInfo<T> {
    type Error = IOError;

    fn try_from(filepath: &Path) -> Result<Self, Self::Error> {
        let mut file = match File::open(filepath) {
            Ok(file) => file,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    // SCOTT: should we keep this? or return err if not found?
                    return Ok(Self {
                        filepath: filepath.to_owned(),
                        data: vec![],
                    });
                }
                _ => return Err(e),
            },
        };
        file.lock_exclusive().unwrap();

        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        file.unlock().unwrap();

        let data_history = Vec::from_ssz_bytes(&bytes).unwrap();

        Ok(Self {
            filepath: filepath.to_owned(),
            data: data_history.to_vec(),
        })
    }
}

#[cfg(test)]
mod single_threaded_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::{
        AttestationData, AttestationDataAndCustodyBit, Checkpoint, Crosslink, Epoch, Hash256,
        Signature, Slot,
    };

    fn attestation_and_custody_bit_builder(
        source: u64,
        target: u64,
    ) -> AttestationDataAndCustodyBit {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let crosslink = Crosslink::default();

        let data = AttestationData {
            beacon_block_root: Hash256::zero(),
            source,
            target,
            crosslink,
        };

        AttestationDataAndCustodyBit {
            data,
            custody_bit: false,
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

        attestation_file.close().unwrap(); // Making sure it's correctly closed
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

        attestation_file.close().unwrap(); // Making sure it's correctly closed
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

        attestation_file.close().unwrap(); // Making sure it's correctly closed
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

        block_file.close().unwrap(); // Making sure it's correctly closed
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

        block_file.close().unwrap(); // Making sure it's correctly closed
    }
}
