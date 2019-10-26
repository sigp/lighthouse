extern crate fs2;

use fs2::FileExt;
use slashing_protection::logic::should_sign_attestation;
use slashing_protection::validator_historical_attestation::ValidatorHistoricalAttestation;
use slashing_protection::validator_historical_block::ValidatorHistoricalBlock;
use ssz::{Decode, Encode};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use types::*;

const BLOCK_HISTORY_FILE: &str = "block.file";
const ATTESTATION_HISTORY_FILE: &str = "attestation.file";

type History<T> = Vec<T>;

trait ShouldSign<U> {
	fn should_sign(&self, challenger: &U) -> bool;
}

impl ShouldSign<AttestationData> for History<ValidatorHistoricalAttestation> {
	fn should_sign (&self, challenger: &AttestationData) -> bool {
		let history = &self[..];
		if should_sign_attestation(challenger, history).is_err() {
			return false
		}
		true
	}
}

#[derive(Debug)]
struct HistoryInfo<T: Encode + Decode> {
    filename: String,
    mutex: Arc<Mutex<History<T>>>,
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

impl<T: Encode + Decode> HistoryInfo<T> {
	pub fn update_and_write(&mut self) -> IOResult<()> {
		let history = self.mutex.lock().unwrap();
		// insert
		let mut file = File::create(self.filename.as_str()).unwrap();
        file.lock_exclusive()?;
		go_to_sleep(100);
        file.write_all(&history.as_ssz_bytes()).expect("HEY");
        file.unlock()?;

		Ok(())
	}
}

impl ShouldSign<AttestationData> for HistoryInfo<ValidatorHistoricalAttestation> {
	fn should_sign(&self, challenger: &AttestationData) -> bool {
		let guard = self.mutex.lock().unwrap();
		let history = &*guard;
	    if let Err(e) = should_sign_attestation(challenger, &history) {
	        println!("{:?}", e);
	        return false;
    	}
		true
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

	for _ in 0..3 {
		let handle = thread::spawn(move || {
			let mut attestation_info: HistoryInfo<ValidatorHistoricalAttestation> = HistoryInfo::try_from(ATTESTATION_HISTORY_FILE).unwrap();
			let mut block_info: HistoryInfo<ValidatorHistoricalBlock> = HistoryInfo::try_from(BLOCK_HISTORY_FILE).unwrap();
			let attestation = attestation_builder(1, 2);
			let res = attestation_info.should_sign(&attestation);
			println!("res: {}", res);
			go_to_sleep(100);
			attestation_info.update_and_write().unwrap();
			block_info.update_and_write().unwrap();
		});
		handles.push(handle);
	}

	for handle in handles {
		handle.join().unwrap();
	}

	println!("DONE");
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

fn build_checkpoint(epoch_num: u64) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::from(epoch_num),
        root: Hash256::zero(),
    }
}

fn should_sign(
    incoming_attestation: &AttestationData,
    historical_attestations: &[ValidatorHistoricalAttestation],
    i: usize,
) -> bool {
    println!("{}: Received for signing", i);
    let ten_millis = time::Duration::from_millis(100);
    if let Err(e) = should_sign_attestation(incoming_attestation, historical_attestations) {
        println!("{:?}", e);
        return false;
    }
    thread::sleep(ten_millis);

    println!("{}: Signed", i);
    true
}