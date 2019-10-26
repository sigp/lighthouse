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

#[derive(Clone, Debug)]
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

    fn write_to_file(&self) -> IOResult<()> {
        let mut file = File::create(&self.filename)?;
        file.lock_exclusive()?;
        file.write_all(&self.history.as_ssz_bytes())?;
        file.unlock()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
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

// #[derive(Clone, Debug)]
// pub struct HistoryInfo {
// 	attestation_info: AttestationHistoryInfo,
// 	block_info: BlockHistoryInfo,
// }

// impl HistoryInfo {
// 	fn new(attestation_info: AttestationHistoryInfo, block_info: BlockHistoryInfo) -> Self {
// 		Self {
// 			attestation_info,
// 			block_info,
// 		}
// 	}
// }

#[derive(Debug)]
struct HistoryInfo<T: Encode + Decode> {
    filename: String,
    mutex: Arc<Mutex<Vec<T>>>,
}

impl<T: Encode + Decode + Clone> TryFrom<&str> for HistoryInfo<T> {
    type Error = &'static str;

    fn try_from(filename: &str) -> Result<Self, Self::Error> {
        let mut file = File::open(filename).unwrap();
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();

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
		let data = self.mutex.lock().unwrap();
		// insert
		let mut file = File::create(self.filename.as_str()).unwrap();
        file.lock_exclusive()?;
        file.write_all(&data.as_ssz_bytes()).expect("HEY");
        file.unlock()?;

		Ok(())
	}
}

fn main() {
    run();
}

fn run() {
	let mut attestation_info: HistoryInfo<ValidatorHistoricalAttestation> = HistoryInfo::try_from(ATTESTATION_HISTORY_FILE).unwrap();
	let mut block_info: HistoryInfo<ValidatorHistoricalBlock> = HistoryInfo::try_from(BLOCK_HISTORY_FILE).unwrap();
	println!("attestation: {:?}", attestation_info);
	println!("block: {:?}", block_info);
	attestation_info.update_and_write().unwrap();
	block_info.update_and_write().unwrap();
}
    // let info = on_boot().unwrap();
    // check_attestation().unwrap();
    // check_block().unwrap();
    // append_data();
    // write_data();
// 
    // println!("{:?}", info);
    // let mut handles = vec![];
    // let data_mutex = Mutex::new(info);
    // let arc_data = Arc::new(data_mutex);
// 
    // for i in 0..3 {
        // let data = Arc::clone(&arc_data);
        // let handle = thread::spawn(move || {
            // println!("{}: Waiting for lock", i);
            // let data = data.lock().unwrap();
            // let attestation_history = &data.attestation_info.history;
            // let incoming_attestation = attestation_builder(3, 2);
            // let _ = should_sign(&incoming_attestation, attestation_history, i);
        // });
        // handles.push(handle);
    // }
// 
    // for handle in handles {
        // handle.join().unwrap();
    // }
// 
    // let data = arc_data.lock().unwrap();
    // data.attestation_info.write_to_file().unwrap();
    // data.block_info.write_to_file().unwrap();
// }

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
// fn on_boot() -> IOResult<(HistoryInfo<AttestationInfo>)> {
    // let mut file = File::open("block.file")?;
    // let mut block_bytes = vec![];
    // file.read_to_end(&mut block_bytes)?;
// 
    // let mut file = File::open("attestation.file")?;
    // let mut attestation_bytes = vec![];
    // file.read_to_end(&mut attestation_bytes)?;
// 
    // let block_history = Vec::from_ssz_bytes(&block_bytes).unwrap();
    // let attestation_history = Vec::from_ssz_bytes(&attestation_bytes).unwrap();
// 
    // let block_info = BlockHistoryInfo::new("block.file", &block_history[..]);
    // let attestation_info =
        // AttestationHistoryInfo::new("attestation.file", &attestation_history[..]);
// 
    // Ok(HistoryInfo::new(attestation_info, block_info))
// }

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

// fn write_to_file(filename: &str, data: &HistoryInfo) -> Result<()> {
// let mut file = File::create(filename)?;

// file.write_all(data.as_ssz_bytes())?;
//
// Ok(())
// }

// Add enum and match it to know if we're creating attestation struct or block struct
// Pass in private key folder?
// fn load_file(filename: &str) -> Result<String> {
// let mut file = File::open(filename)?;
// file.lock_exclusive()?;
//
//
// let mut buffer = Vec::new();
// file.read_to_end(&mut buffer)?;
// let mut res = String::new();
//
// for num in buffer.iter() {
// res.push(*num as char);
// }
//
// file.unlock()?;
//
// Ok(res)
// }
