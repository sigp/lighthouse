//! This crate should eventually represent the structure at this repo:
//!
//! https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus/testnet1
//!
//! It is not accurate at the moment, we include extra files and we also don't support a few
//! others. We are unable to confirm to the repo until we have the following PR merged:
//!
//! https://github.com/sigp/lighthouse/pull/605

use std::fs::{create_dir_all, File};
use std::path::PathBuf;

pub const ADDRESS_FILE: &str = "deposit_contract.txt";
pub const DEPLOY_BLOCK_FILE: &str = "deploy_block.txt";
pub const MIN_GENESIS_TIME_FILE: &str = "min_genesis_time.txt";

#[derive(Clone, PartialEq, Debug)]
pub struct Eth2TestnetDir {
    pub deposit_contract_address: String,
    pub deposit_contract_deploy_block: u64,
    pub min_genesis_time: u64,
}

impl Eth2TestnetDir {
    pub fn new(
        base_dir: PathBuf,
        deposit_contract_address: String,
        deposit_contract_deploy_block: u64,
        min_genesis_time: u64,
    ) -> Result<Self, String> {
        if base_dir.exists() {
            return Err("Testnet directory already exists".to_string());
        }

        create_dir_all(&base_dir)
            .map_err(|e| format!("Unable to create testnet directory: {:?}", e))?;

        File::create(base_dir.join(ADDRESS_FILE))
            .map_err(|e| format!("Unable to create {}: {:?}", ADDRESS_FILE, e))
            .and_then(|file| {
                serde_json::to_writer(file, &deposit_contract_address)
                    .map_err(|e| format!("Unable to write {}: {:?}", ADDRESS_FILE, e))
            })?;

        File::create(base_dir.join(DEPLOY_BLOCK_FILE))
            .map_err(|e| format!("Unable to create {}: {:?}", DEPLOY_BLOCK_FILE, e))
            .and_then(|file| {
                serde_json::to_writer(file, &deposit_contract_deploy_block)
                    .map_err(|e| format!("Unable to write {}: {:?}", DEPLOY_BLOCK_FILE, e))
            })?;

        File::create(base_dir.join(MIN_GENESIS_TIME_FILE))
            .map_err(|e| format!("Unable to create {}: {:?}", MIN_GENESIS_TIME_FILE, e))
            .and_then(|file| {
                serde_json::to_writer(file, &min_genesis_time)
                    .map_err(|e| format!("Unable to write {}: {:?}", MIN_GENESIS_TIME_FILE, e))
            })?;

        Ok(Self {
            deposit_contract_address,
            deposit_contract_deploy_block,
            min_genesis_time,
        })
    }

    pub fn load(base_dir: PathBuf) -> Result<Self, String> {
        let deposit_contract_address = File::open(base_dir.join(ADDRESS_FILE))
            .map_err(|e| format!("Unable to open {}: {:?}", ADDRESS_FILE, e))
            .and_then(|file| {
                serde_json::from_reader(file)
                    .map_err(|e| format!("Unable to parse {}: {:?}", ADDRESS_FILE, e))
            })?;

        let deposit_contract_deploy_block = File::open(base_dir.join(DEPLOY_BLOCK_FILE))
            .map_err(|e| format!("Unable to open {}: {:?}", DEPLOY_BLOCK_FILE, e))
            .and_then(|file| {
                serde_json::from_reader(file)
                    .map_err(|e| format!("Unable to parse {}: {:?}", DEPLOY_BLOCK_FILE, e))
            })?;

        let min_genesis_time = File::open(base_dir.join(MIN_GENESIS_TIME_FILE))
            .map_err(|e| format!("Unable to open {}: {:?}", MIN_GENESIS_TIME_FILE, e))
            .and_then(|file| {
                serde_json::from_reader(file)
                    .map_err(|e| format!("Unable to parse {}: {:?}", MIN_GENESIS_TIME_FILE, e))
            })?;

        Ok(Self {
            deposit_contract_address,
            deposit_contract_deploy_block,
            min_genesis_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn round_trip() {
        let temp_dir = TempDir::new("eth2_testnet_test").expect("should create temp dir");
        let base_dir = PathBuf::from(temp_dir.path().join("my_testnet"));
        let deposit_contract_address = "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413".to_string();
        let deposit_contract_deploy_block = 42;
        let min_genesis_time = 1337;

        let testnet = Eth2TestnetDir::new(
            base_dir.clone(),
            deposit_contract_address.clone(),
            deposit_contract_deploy_block,
            min_genesis_time,
        )
        .expect("should create struct");

        let decoded = Eth2TestnetDir::load(base_dir).expect("should load struct");

        assert_eq!(
            decoded.deposit_contract_address, deposit_contract_address,
            "deposit_contract_address"
        );
        assert_eq!(
            decoded.deposit_contract_deploy_block, deposit_contract_deploy_block,
            "deposit_contract_deploy_block"
        );
        assert_eq!(
            decoded.min_genesis_time, min_genesis_time,
            "min_genesis_time"
        );

        assert_eq!(testnet, decoded, "should decode as encoded");
    }
}
