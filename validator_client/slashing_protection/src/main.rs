extern crate fs2;

use fs2::FileExt;
use std::io::Result;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use slashing_protection::validator_historical_attestation::ValidatorHistoricalAttestation;
use slashing_protection::validator_historical_block::ValidatorHistoricalBlock;
use slashing_protection::logic::{should_sign_attestation, AttestationError};
use std::sync::{Mutex, Arc};
use std::thread;
use std::time;
use types::*;

const FILENAME: &str = "file.lock";

#[derive(Debug, Clone)]
struct BlockHistoryInfo {
	filename: String,
	history: Vec<ValidatorHistoricalBlock>,
}

impl BlockHistoryInfo {
	fn new(filename: &str, history: &[ValidatorHistoricalBlock]) -> Self {
		Self {
			filename: String::from(filename),
			history: history.to_vec(),
		}
	}
}

#[derive(Debug, Clone)]
struct AttestationHistoryInfo {
	filename: String,
	history: Vec<ValidatorHistoricalAttestation>,
}

impl AttestationHistoryInfo {
	fn new(filename: &str, history: &[ValidatorHistoricalAttestation]) -> Self {
		Self {
			filename: String::from(filename),
			history: history.to_vec(),
		}
	}
}

#[derive(Debug, Clone)]
pub struct HistoryInfo {
	attestation_info: AttestationHistoryInfo,
	block_info: BlockHistoryInfo,
}

impl HistoryInfo {
	fn new(attestation_info: AttestationHistoryInfo, block_info: BlockHistoryInfo) -> Self {
		Self {
			attestation_info,
			block_info,
		}
	}
}

fn main() {
	run();
}

fn run() {
	let info = on_boot().unwrap();
	let mut handles = vec![];
	let data_mutex = Mutex::new(info);
	let arc_data = Arc::new(data_mutex);

	for i in 0..3 {
		let data = Arc::clone(&arc_data);
		let handle = thread::spawn(move || {
			println!("{}: Waiting for lock", i);
			let data = data.lock().unwrap();
			let attestation_history = &data.attestation_info.history;
			let incoming_attestation = attestation_builder(3, 2);
			let _ = should_sign(&incoming_attestation, attestation_history, i);
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

fn build_checkpoint(epoch_num: u64) -> Checkpoint {
	Checkpoint {
		epoch: Epoch::from(epoch_num),
		root: Hash256::zero(),
	}
}

/// Sets a lock on the history files, reads files, deserialize them, loads them
/// into memory and returns a tuple containing two structs (block_history_data, attestation_history_data)
fn on_boot() -> Result<(HistoryInfo)>{
	let mut block_history = vec![];
	let mut attestation_history = vec![];

	let attestation_data = attestation_builder(0, 1);

	let old_attestation = AttestationDataAndCustodyBit {
		data: attestation_data,
		custody_bit: false,
	};
	let old_block = BeaconBlockHeader {
		slot: Slot::from(0u64),
		parent_root: Hash256::random(),
		state_root: Hash256::zero(),
		body_root: Hash256::zero(),
		signature: Signature::empty_signature(),
	};

	let historical_attestation = ValidatorHistoricalAttestation::from(&old_attestation);
	let historical_block = ValidatorHistoricalBlock::from(&old_block);


	block_history.push(historical_block);
	attestation_history.push(historical_attestation);

	let block_info = BlockHistoryInfo::new("block.file", &block_history[..]);
	let attestation_info = AttestationHistoryInfo::new("attestation.file", &attestation_history[..]);

	Ok(HistoryInfo::new(attestation_info, block_info))
}

fn should_sign(incoming_attestation: &AttestationData, historical_attestations: &[ValidatorHistoricalAttestation], i: usize) -> bool {
	println!("{}: Received for signing", i);
	let ten_millis = time::Duration::from_millis(100);
	if let Err(e) = should_sign_attestation(incoming_attestation, historical_attestations) {
		println!("{:?}", e);
		return false
	}
	thread::sleep(ten_millis);

	println!("{}: Signed", i);
	true
}

fn write_to_file(filename: &str) -> Result<()> {
	let mut file = File::create(filename)?;

	let bytes = vec![0x41, 0x42, 0x43];

	file.write_all(&bytes)?;

	Ok(())
}

// Add enum and match it to know if we're creating attestation struct or block struct
// Pass in private key folder?
fn load_file(filename: &str) -> Result<String> {
	let mut file = File::open(filename)?;
	file.lock_exclusive()?;
	

	let mut buffer = Vec::new();
	file.read_to_end(&mut buffer)?;
	let mut res = String::new();

	for num in buffer.iter() {
		res.push(*num as char);
	}

	// buffer deserialize
	file.unlock()?;

	Ok(res)
}