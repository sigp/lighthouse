extern crate fs2;

use fs2::FileExt;
use std::io::Result;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use types::Epoch;
use slashing_protection::validator_historical_attestation::ValidatorHistoricalAttestation;

const FILENAME: &str = "file.lock";

fn main() {
	write_to_file(FILENAME).expect("Should be able to write to file"); // care
	let data = load_file(FILENAME).expect("Should be able to load file"); // care
	println!("{}", data);
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
	// file.unlock()?;

	Ok(res)
}