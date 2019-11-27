//! This crate should eventually represent the structure at this repo:
//!
//! https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus/testnet1
//!
//! It is not accurate at the moment, we include extra files and we also don't support a few
//! others. We are unable to confirm to the repo until we have the following PR merged:
//!
//! https://github.com/sigp/lighthouse/pull/605

use eth2_libp2p::Enr;
use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use types::Address;

pub const ADDRESS_FILE: &str = "deposit_contract.txt";
pub const DEPLOY_BLOCK_FILE: &str = "deploy_block.txt";
pub const MIN_GENESIS_TIME_FILE: &str = "min_genesis_time.txt";
pub const BOOT_NODES_FILE: &str = "boot_nodes.json";

#[derive(Clone, PartialEq, Debug)]
pub struct Eth2TestnetDir {
    deposit_contract_address: String,
    pub deposit_contract_deploy_block: u64,
    pub min_genesis_time: u64,
    pub boot_nodes: Vec<Enr>,
}

impl Eth2TestnetDir {
    pub fn new(
        base_dir: PathBuf,
        deposit_contract_address: String,
        deposit_contract_deploy_block: u64,
        min_genesis_time: u64,
        boot_nodes: Vec<Enr>,
    ) -> Result<Self, String> {
        if base_dir.exists() {
            return Err("Testnet directory already exists".to_string());
        }

        create_dir_all(&base_dir)
            .map_err(|e| format!("Unable to create testnet directory: {:?}", e))?;

        macro_rules! write_to_file {
            ($file: ident, $variable: ident) => {
                File::create(base_dir.join($file))
                    .map_err(|e| format!("Unable to create {}: {:?}", $file, e))
                    .and_then(|file| {
                        serde_json::to_writer(file, &$variable)
                            .map_err(|e| format!("Unable to write {}: {:?}", $file, e))
                    })?;
            };
        }

        write_to_file!(ADDRESS_FILE, deposit_contract_address);
        write_to_file!(DEPLOY_BLOCK_FILE, deposit_contract_deploy_block);
        write_to_file!(MIN_GENESIS_TIME_FILE, min_genesis_time);
        write_to_file!(BOOT_NODES_FILE, boot_nodes);

        Ok(Self {
            deposit_contract_address,
            deposit_contract_deploy_block,
            min_genesis_time,
            boot_nodes,
        })
    }

    pub fn load(base_dir: PathBuf) -> Result<Self, String> {
        macro_rules! load_from_file {
            ($file: ident) => {
                File::open(base_dir.join($file))
                    .map_err(|e| format!("Unable to open {}: {:?}", $file, e))
                    .and_then(|file| {
                        serde_json::from_reader(file)
                            .map_err(|e| format!("Unable to parse {}: {:?}", $file, e))
                    })?;
            };
        }

        let deposit_contract_address = load_from_file!(ADDRESS_FILE);
        let deposit_contract_deploy_block = load_from_file!(DEPLOY_BLOCK_FILE);
        let min_genesis_time = load_from_file!(MIN_GENESIS_TIME_FILE);
        let boot_nodes = load_from_file!(BOOT_NODES_FILE);

        Ok(Self {
            deposit_contract_address,
            deposit_contract_deploy_block,
            min_genesis_time,
            boot_nodes,
        })
    }

    pub fn deposit_contract_address(&self) -> Result<Address, String> {
        if self.deposit_contract_address.starts_with("0x") {
            self.deposit_contract_address[2..]
                .parse()
                .map_err(|e| format!("Corrupted address, unable to parse: {:?}", e))
        } else {
            Err("Corrupted address, must start with 0x".to_string())
        }
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
            // TODO: add some Enr for testing.
            vec![],
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
