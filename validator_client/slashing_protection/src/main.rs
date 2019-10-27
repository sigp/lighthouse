extern crate fs2;

use fs2::FileExt;
use parking_lot::Mutex;
use slashing_protection::logic::should_sign_attestation;
use slashing_protection::logic::should_sign_block;
use slashing_protection::validator_historical_attestation::ValidatorHistoricalAttestation;
use slashing_protection::validator_historical_block::ValidatorHistoricalBlock;
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

trait MyTrait<U, T> {
    fn signing_func(&self, challenger: &U, history: &[T]) -> Result<usize, &'static str>;
}

impl MyTrait<AttestationData, ValidatorHistoricalAttestation>
    for HistoryInfo<ValidatorHistoricalAttestation>
{
    fn signing_func(
        &self,
        challenger: &AttestationData,
        history: &[ValidatorHistoricalAttestation],
    ) -> Result<usize, &'static str> {
        should_sign_attestation(challenger, history).map_err(|_| "invalid attestation")
    }
}

impl MyTrait<BeaconBlockHeader, ValidatorHistoricalBlock>
    for HistoryInfo<ValidatorHistoricalBlock>
{
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
        go_to_sleep(100);
        file.write_all(&history.as_ssz_bytes()).expect("HEY");
        file.unlock()?;

        Ok(())
    }

    fn should_sign<U>(&self, challenger: &U) -> Result<usize, &'static str>
    where
        Self: MyTrait<U, T>,
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

// fn should_sign(
// incoming_attestation: &AttestationData,
// historical_attestations: &[ValidatorHistoricalAttestation],
// i: usize,
// ) -> bool {
// println!("{}: Received for signing", i);
// let ten_millis = time::Duration::from_millis(100);
// if let Err(e) = should_sign_attestation(incoming_attestation, historical_attestations) {
// println!("{:?}", e);
// return false;
// }
// thread::sleep(ten_millis);
//
// println!("{}: Signed", i);
// true
// }
