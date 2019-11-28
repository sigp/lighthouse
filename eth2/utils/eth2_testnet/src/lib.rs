//! This crate should eventually represent the structure at this repo:
//!
//! https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus/testnet1
//!
//! It is not accurate at the moment, we include extra files and we also don't support a few
//! others. We are unable to confirm to the repo until we have the following PR merged:
//!
//! https://github.com/sigp/lighthouse/pull/605

use eth2_libp2p::Enr;
use ssz::{Decode, Encode};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use types::{Address, BeaconState, EthSpec, YamlConfig};

pub const ADDRESS_FILE: &str = "deposit_contract.txt";
pub const DEPLOY_BLOCK_FILE: &str = "deploy_block.txt";
pub const BOOT_NODES_FILE: &str = "boot_enr.yaml";
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub const YAML_CONFIG_FILE: &str = "config.yaml";

pub const HARDCODED_YAML_CONFIG: &[u8] = include_bytes!("../testnet/config.yaml");
pub const HARDCODED_DEPLOY_BLOCK: &[u8] = include_bytes!("../testnet/deploy_block.txt");
pub const HARDCODED_DEPOSIT_CONTRACT: &[u8] = include_bytes!("../testnet/deposit_contract.txt");
pub const HARDCODED_GENESIS_STATE: &[u8] = include_bytes!("../testnet/genesis.ssz");

#[derive(Clone, PartialEq, Debug)]
pub struct Eth2TestnetDir<E: EthSpec> {
    pub deposit_contract_address: String,
    pub deposit_contract_deploy_block: u64,
    pub boot_enr: Option<Vec<Enr>>,
    pub genesis_state: Option<BeaconState<E>>,
    pub yaml_config: Option<YamlConfig>,
}

impl<E: EthSpec> Eth2TestnetDir<E> {
    pub fn create_hardcoded(base_dir: PathBuf) -> Result<Self, String> {
        if base_dir.exists() {
            return Err("Testnet directory already exists".to_string());
        }

        create_dir_all(&base_dir)
            .map_err(|e| format!("Unable to create testnet directory: {:?}", e))?;

        macro_rules! write_bytes_to_file {
            ($file: ident, $bytes: expr) => {
                File::create(base_dir.join($file))
                    .map_err(|e| format!("Unable to create {}: {:?}", $file, e))
                    .and_then(|mut file| {
                        file.write_all($bytes)
                            .map_err(|e| format!("Unable to write bytes to {}: {}", $file, e))
                    })?;
            };
        }

        write_bytes_to_file!(YAML_CONFIG_FILE, HARDCODED_YAML_CONFIG);
        write_bytes_to_file!(DEPLOY_BLOCK_FILE, HARDCODED_DEPLOY_BLOCK);
        write_bytes_to_file!(ADDRESS_FILE, HARDCODED_DEPOSIT_CONTRACT);
        write_bytes_to_file!(GENESIS_STATE_FILE, HARDCODED_GENESIS_STATE);

        Self::load(base_dir)
    }

    // Write the files to the directory, only if the directory doesn't already exist.
    pub fn write_to_file(&self, base_dir: PathBuf) -> Result<(), String> {
        if base_dir.exists() {
            return Err("Testnet directory already exists".to_string());
        }

        self.force_write_to_file(base_dir)
    }

    // Write the files to the directory, even if the directory already exists.
    pub fn force_write_to_file(&self, base_dir: PathBuf) -> Result<(), String> {
        create_dir_all(&base_dir)
            .map_err(|e| format!("Unable to create testnet directory: {:?}", e))?;

        macro_rules! write_to_yaml_file {
            ($file: ident, $variable: expr) => {
                File::create(base_dir.join($file))
                    .map_err(|e| format!("Unable to create {}: {:?}", $file, e))
                    .and_then(|mut file| {
                        let yaml = serde_yaml::to_string(&$variable)
                            .map_err(|e| format!("Unable to YAML encode {}: {:?}", $file, e))?;

                        // Remove the doc header from the YAML file.
                        //
                        // This allows us to play nice with other clients that are expecting
                        // plain-text, not YAML.
                        let no_doc_header = if yaml.starts_with("---\n") {
                            &yaml[4..]
                        } else {
                            &yaml
                        };

                        file.write_all(no_doc_header.as_bytes())
                            .map_err(|e| format!("Unable to write {}: {:?}", $file, e))
                    })?;
            };
        }

        write_to_yaml_file!(ADDRESS_FILE, self.deposit_contract_address);
        write_to_yaml_file!(DEPLOY_BLOCK_FILE, self.deposit_contract_deploy_block);

        if let Some(boot_enr) = &self.boot_enr {
            write_to_yaml_file!(BOOT_NODES_FILE, boot_enr);
        }

        if let Some(yaml_config) = &self.yaml_config {
            write_to_yaml_file!(YAML_CONFIG_FILE, yaml_config);
        }

        // The genesis state is a special case because it uses SSZ, not YAML.
        if let Some(genesis_state) = &self.genesis_state {
            let file = base_dir.join(GENESIS_STATE_FILE);

            File::create(&file)
                .map_err(|e| format!("Unable to create {:?}: {:?}", file, e))
                .and_then(|mut file| {
                    file.write_all(&genesis_state.as_ssz_bytes())
                        .map_err(|e| format!("Unable to write {:?}: {:?}", file, e))
                })?;
        }

        Ok(())
    }

    pub fn load(base_dir: PathBuf) -> Result<Self, String> {
        macro_rules! load_from_file {
            ($file: ident) => {
                File::open(base_dir.join($file))
                    .map_err(|e| format!("Unable to open {}: {:?}", $file, e))
                    .and_then(|file| {
                        serde_yaml::from_reader(file)
                            .map_err(|e| format!("Unable to parse {}: {:?}", $file, e))
                    })?;
            };
        }

        macro_rules! optional_load_from_file {
            ($file: ident) => {
                if base_dir.join($file).exists() {
                    Some(load_from_file!($file))
                } else {
                    None
                }
            };
        }

        let deposit_contract_address = load_from_file!(ADDRESS_FILE);
        let deposit_contract_deploy_block = load_from_file!(DEPLOY_BLOCK_FILE);
        let boot_enr = optional_load_from_file!(BOOT_NODES_FILE);
        let yaml_config = optional_load_from_file!(YAML_CONFIG_FILE);

        // The genesis state is a special case because it uses SSZ, not YAML.
        let file = base_dir.join(GENESIS_STATE_FILE);
        let genesis_state = if base_dir.join(&file).exists() {
            Some(
                File::open(base_dir.join(&file))
                    .map_err(|e| format!("Unable to open {:?}: {:?}", file, e))
                    .and_then(|mut file| {
                        let mut bytes = vec![];
                        file.read_to_end(&mut bytes)
                            .map_err(|e| format!("Unable to read {:?}: {:?}", file, e))?;

                        BeaconState::from_ssz_bytes(&bytes)
                            .map_err(|e| format!("Unable to SSZ decode {:?}: {:?}", file, e))
                    })?,
            )
        } else {
            None
        };

        Ok(Self {
            deposit_contract_address,
            deposit_contract_deploy_block,
            boot_enr,
            genesis_state,
            yaml_config,
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
    use types::{Eth1Data, Hash256, MinimalEthSpec, YamlConfig};

    type E = MinimalEthSpec;

    #[test]
    fn round_trip() {
        let spec = &E::default_spec();

        let eth1_data = Eth1Data {
            deposit_root: Hash256::zero(),
            deposit_count: 0,
            block_hash: Hash256::zero(),
        };

        // TODO: figure out how to generate ENR and add some here.
        let boot_enr = None;
        let genesis_state = Some(BeaconState::new(42, eth1_data, spec));
        let yaml_config = Some(YamlConfig::from_spec::<E>(spec));

        do_test::<E>(boot_enr, genesis_state.clone(), yaml_config.clone());
        do_test::<E>(None, None, None);
    }

    fn do_test<E: EthSpec>(
        boot_enr: Option<Vec<Enr>>,
        genesis_state: Option<BeaconState<E>>,
        yaml_config: Option<YamlConfig>,
    ) {
        let temp_dir = TempDir::new("eth2_testnet_test").expect("should create temp dir");
        let base_dir = PathBuf::from(temp_dir.path().join("my_testnet"));
        let deposit_contract_address = "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413".to_string();
        let deposit_contract_deploy_block = 42;

        let testnet: Eth2TestnetDir<E> = Eth2TestnetDir {
            deposit_contract_address: deposit_contract_address.clone(),
            deposit_contract_deploy_block: deposit_contract_deploy_block,
            boot_enr,
            genesis_state,
            yaml_config,
        };

        testnet
            .write_to_file(base_dir.clone())
            .expect("should write to file");

        let decoded = Eth2TestnetDir::load(base_dir).expect("should load struct");

        assert_eq!(testnet, decoded, "should decode as encoded");
    }
}
