extern crate fs2;

use fs2::FileExt;
use parking_lot::Mutex;
use slashing_protection::attester_slashings::{should_sign_attestation, ValidatorHistoricalAttestation};
use slashing_protection::proposer_slashings::{should_sign_block, ValidatorHistoricalBlock};
use ssz::{Decode, Encode};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::time;
use types::*;

const BLOCK_HISTORY_FILE: &str = "block.file";
const ATTESTATION_HISTORY_FILE: &str = "attestation.file";

trait MyTrait<T> {
    type U;

    fn signing_func(&self, challenger: &Self::U, history: &[T]) -> Result<usize, &'static str>;
}

impl MyTrait<ValidatorHistoricalAttestation> for HistoryInfo<ValidatorHistoricalAttestation> {
    type U = AttestationData;

    fn signing_func(
        &self,
        challenger: &AttestationData,
        history: &[ValidatorHistoricalAttestation],
    ) -> Result<usize, &'static str> {
        should_sign_attestation(challenger, history).map_err(|_| "invalid attestation")
    }
}

impl MyTrait<ValidatorHistoricalBlock> for HistoryInfo<ValidatorHistoricalBlock> {
    type U = BeaconBlockHeader;

    fn signing_func(
        &self,
        challenger: &BeaconBlockHeader,
        history: &[ValidatorHistoricalBlock],
    ) -> Result<usize, &'static str> {
        should_sign_block(challenger, history)
    }
}

#[derive(Debug)]
struct HistoryInfo<T: Encode + Decode + Clone> {
    filename: String,
    mutex: Arc<Mutex<Vec<T>>>,
}

impl<T: Encode + Decode + Clone> HistoryInfo<T> {
    pub fn update_and_write(&mut self) -> IOResult<()> {
        let history = self.mutex.lock();
        // insert
        let mut file = File::create(self.filename.as_str()).unwrap();
        file.lock_exclusive()?;
        go_to_sleep(100); // nope
        file.write_all(&history.as_ssz_bytes()).expect("HEY"); // nope
        file.unlock()?;

        Ok(())
    }

    fn should_sign(
        &self,
        challenger: &<HistoryInfo<T> as MyTrait<T>>::U,
    ) -> Result<usize, &'static str>
    where
        Self: MyTrait<T>,
    {
        let guard = self.mutex.lock();
        let history = &guard[..];
        self.signing_func(challenger, history)
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

        let history = Vec::from_ssz_bytes(&bytes).unwrap();
        let attestation_history = history.to_vec();

        let data_mutex = Mutex::new(attestation_history);
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

    for _ in 0..1 {
        let handle = thread::spawn(move || {
            let mut attestation_info: HistoryInfo<ValidatorHistoricalAttestation> =
                HistoryInfo::try_from(ATTESTATION_HISTORY_FILE).unwrap();
            let mut block_info: HistoryInfo<ValidatorHistoricalBlock> =
                HistoryInfo::try_from(BLOCK_HISTORY_FILE).unwrap();
            println!("{:?}", block_info);
            let attestation = attestation_builder(1, 2);
            let block = block_builder(1);
            let res = attestation_info.should_sign(&attestation);
            println!("res: {:?}", res);
            let res = block_info.should_sign(&block);
            println!("res: {:?}", res);
            go_to_sleep(100);
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
