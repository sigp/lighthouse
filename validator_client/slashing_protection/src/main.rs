extern crate fs2;

use fs2::FileExt;
use parking_lot::Mutex;
use slashing_protection::attester_slashings::{check_for_attester_slashing, SignedAttestation};
use slashing_protection::enums::{NotSafe, Safe};
use slashing_protection::proposer_slashings::{check_for_proposer_slashing, SignedBlock};
use ssz::{Decode, Encode};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Read, Result as IOResult, Write};
use std::sync::Arc;
use std::thread;
use std::time;
use types::*;

const BLOCK_HISTORY_FILE: &str = "block.file";
const ATTESTATION_HISTORY_FILE: &str = "attestation.file";

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
}

#[derive(Debug)]
struct HistoryInfo<T: Encode + Decode + Clone> {
    filename: String,
    mutex: Arc<Mutex<Vec<T>>>,
}

impl<T: Encode + Decode + Clone> HistoryInfo<T> {
    pub fn update_and_write(&mut self) -> IOResult<()> {
        println!("{}: waiting for mutex", self.filename);
        let data_history = self.mutex.lock(); // SCOTT: check here please
        println!("{}: mutex acquired", self.filename);
        // insert
        let mut file = File::create(self.filename.as_str()).unwrap();
        println!("{}: waiting for file", self.filename);
        file.lock_exclusive()?;
        println!("{}: file acquired", self.filename);
        // go_to_sleep(100); // nope
        file.write_all(&data_history.as_ssz_bytes()).expect("HEY"); // nope
        file.unlock()?;
        println!("{}: file unlocked", self.filename);

        Ok(())
    }

    fn check_for_slashing(
        &self,
        incoming_data: &<HistoryInfo<T> as SafeFromSlashing<T>>::U,
    ) -> Result<Safe, NotSafe>
    where
        Self: SafeFromSlashing<T>,
    {
        let guard = self.mutex.lock();
        let data_history = &guard[..];
        self.verify_and_get_index(incoming_data, data_history)
    }
}

impl<T: Encode + Decode + Clone> TryFrom<&str> for HistoryInfo<T> {
    type Error = &'static str;

    fn try_from(filename: &str) -> Result<Self, Self::Error> {
        let mut file = File::open(filename).unwrap();
        file.lock_exclusive().unwrap();
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        file.unlock().unwrap();

        let data_history = Vec::from_ssz_bytes(&bytes).unwrap();
        let attestation_data_history = data_history.to_vec();

        let data_mutex = Mutex::new(attestation_data_history);
        let arc_data = Arc::new(data_mutex);

        Ok(Self {
            filename: filename.to_string(),
            mutex: arc_data,
        })
    }
}

fn main() {
    run();
}

fn go_to_sleep(time: u64) {
    let ten_millis = time::Duration::from_millis(time);
    thread::sleep(ten_millis);
}

fn run() {
    let mut handles = vec![];

    for _ in 0..4 {
        let handle = thread::spawn(move || {
            let mut attestation_info: HistoryInfo<SignedAttestation> =
                HistoryInfo::try_from(ATTESTATION_HISTORY_FILE).unwrap();
            let mut block_info: HistoryInfo<SignedBlock> =
                HistoryInfo::try_from(BLOCK_HISTORY_FILE).unwrap();
            let attestation = attestation_builder(1, 2);
            let block = block_builder(1);
            let res = attestation_info.check_for_slashing(&attestation);
            let res = block_info.check_for_slashing(&block);
            go_to_sleep(1000);
            attestation_info.update_and_write().unwrap();
            block_info.update_and_write().unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

fn attestation_builder(source: u64, target: u64) -> AttestationData {
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
