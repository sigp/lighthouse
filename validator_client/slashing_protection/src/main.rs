extern crate fs2;

use fs2::FileExt;
use std::io::Result;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use types::Epoch;
use slashing_protection::validator_historical_attestation::ValidatorHistoricalAttestation;
use slashing_protection::validator_historical_block::ValidatorHistoricalBlock;
use std::sync::{Mutex, Arc};
use std::thread;
use std::time;

const FILENAME: &str = "file.lock";

fn main() {
	let (a, b) = on_boot().unwrap();
	println!("{:?}, {:?}", a, b);
	write_to_file(FILENAME).expect("Should be able to write");
	let mut handles = vec![];
	let data_mutex = Mutex::new(load_file(FILENAME).expect("Should be able to load file"));
	let arc_data = Arc::new(data_mutex);

	for i in 0..3 {
		let data = Arc::clone(&arc_data);
		let handle = thread::spawn(move || {
			println!("{}: Waiting for lock", i);
			let data = data.lock().unwrap();
			let _ = should_sign(data.to_string(), i);
		});
		handles.push(handle);
	}

	for handle in handles {
		handle.join().unwrap();
	}
}

#[derive(Debug, Clone)]
pub struct BlockHistoryInfo {
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
pub struct AttestationHistoryInfo {
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

/// Sets a lock on the history files, reads files, deserialize them, loads them
/// into memory and returns a tuple containing two structs (block_history_data, attestation_history_data)
fn on_boot() -> Result<((BlockHistoryInfo, AttestationHistoryInfo))>{
	let mut block_history = vec![];
	let mut attestation_history = vec![];
	for i in 0..3 {
		let historical_block = ValidatorHistoricalBlock::new(
			Epoch::new(i as u64),
			&[i; 4],
		);
		let historical_attestation = ValidatorHistoricalAttestation::new(
			Epoch::new(i as u64),
			Epoch::new(i as u64 + 1),
			&[i; 4],
		);
		block_history.push(historical_block);
		attestation_history.push(historical_attestation);
	}
	let block_info = BlockHistoryInfo::new("block.file", &block_history);
	let attestation_info = AttestationHistoryInfo::new("attestation.file", &attestation_history);
	Ok((block_info, attestation_info))
}

fn should_sign(mut attestation: String, i: usize) -> Result<()> {
	println!("{}: Received for signing", i);
	attestation.push('Z');
	let ten_millis = time::Duration::from_millis(100);
	thread::sleep(ten_millis);

	println!("{}: Signed", i);
	Ok(())
}
fn write_to_file(filename: &str) -> Result<()> {
	let mut file = File::create(filename)?;

	let source = Epoch::new(2);
	let target = Epoch::new(3);
	let root = vec![0x41, 0x42, 0x43];
	let mut history = Vec::new();
	history.push(ValidatorHistoricalAttestation::new(source, target, &root));

	file.write_all(&root)?;

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

#[cfg(test)]
mod tests {
	use super::*;
	use std::thread;

	#[test]
	fn basic() {
		thread::spawn(|| {
			write_to_file(FILENAME).expect("Should be able to write");
			let data_mutex = Mutex::new(load_file(FILENAME).expect("Should be able to load file"));
			println!("{:?}", data_mutex);
		});
	}
}