//! Provides the `Eth2NetworkConfig` struct which defines the configuration of an eth2 network or
//! test-network (aka "testnet").
//!
//! Whilst the `Eth2NetworkConfig` struct can be used to read a specification from a directory at
//! runtime, this crate also includes some pre-defined network configurations "built-in" to the
//! binary itself (the most notable of these being the "mainnet" configuration). When a network is
//! "built-in", the  genesis state and configuration files is included in the final binary via the
//! `std::include_bytes` macro. This provides convenience to the user, the binary is self-sufficient
//! and does not require the configuration to be read from the filesystem at runtime.
//!
//! To add a new built-in testnet, add it to the `define_hardcoded_nets` invocation in the `eth2_config`
//! crate.

use enr::{CombinedKey, Enr};
use eth2_config::{instantiate_hardcoded_nets, HardcodedNet};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use types::{BeaconState, ChainSpec, Config, EthSpec, EthSpecId};

pub const DEPLOY_BLOCK_FILE: &str = "deploy_block.txt";
pub const BOOT_ENR_FILE: &str = "boot_enr.yaml";
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub const BASE_CONFIG_FILE: &str = "config.yaml";

// Creates definitions for:
//
// - Each of the `HardcodedNet` values (e.g., `MAINNET`, `PYRMONT`, etc).
// - `HARDCODED_NETS: &[HardcodedNet]`
// - `HARDCODED_NET_NAMES: &[&'static str]`
instantiate_hardcoded_nets!(eth2_config);

pub const DEFAULT_HARDCODED_NETWORK: &str = "mainnet";

/// Specifies an Eth2 network.
///
/// See the crate-level documentation for more details.
#[derive(Clone, PartialEq, Debug)]
pub struct Eth2NetworkConfig {
    /// Note: instead of the block where the contract is deployed, it is acceptable to set this
    /// value to be the block number where the first deposit occurs.
    pub deposit_contract_deploy_block: u64,
    pub boot_enr: Option<Vec<Enr<CombinedKey>>>,
    pub genesis_state_bytes: Option<Vec<u8>>,
    pub config: Config,
}

impl Eth2NetworkConfig {
    /// When Lighthouse is built it includes zero or more "hardcoded" network specifications. This
    /// function allows for instantiating one of these nets by name.
    pub fn constant(name: &str) -> Result<Option<Self>, String> {
        HARDCODED_NETS
            .iter()
            .find(|net| net.name == name)
            .map(Self::from_hardcoded_net)
            .transpose()
    }

    /// Instantiates `Self` from a `HardcodedNet`.
    fn from_hardcoded_net(net: &HardcodedNet) -> Result<Self, String> {
        Ok(Self {
            deposit_contract_deploy_block: serde_yaml::from_reader(net.deploy_block)
                .map_err(|e| format!("Unable to parse deploy block: {:?}", e))?,
            boot_enr: Some(
                serde_yaml::from_reader(net.boot_enr)
                    .map_err(|e| format!("Unable to parse boot enr: {:?}", e))?,
            ),
            genesis_state_bytes: Some(net.genesis_state_bytes.to_vec())
                .filter(|bytes| !bytes.is_empty()),
            config: serde_yaml::from_reader(net.config)
                .map_err(|e| format!("Unable to parse yaml config: {:?}", e))?,
        })
    }

    /// Returns an identifier that should be used for selecting an `EthSpec` instance for this
    /// network configuration.
    pub fn eth_spec_id(&self) -> Result<EthSpecId, String> {
        self.config
            .eth_spec_id()
            .ok_or_else(|| "Config does not match any known preset".to_string())
    }

    /// Returns `true` if this configuration contains a `BeaconState`.
    pub fn beacon_state_is_known(&self) -> bool {
        self.genesis_state_bytes.is_some()
    }

    /// Construct a consolidated `ChainSpec` from the YAML config.
    pub fn chain_spec<E: EthSpec>(&self) -> Result<ChainSpec, String> {
        ChainSpec::from_config::<E>(&self.config).ok_or_else(|| {
            format!(
                "YAML configuration incompatible with spec constants for {}",
                E::spec_name()
            )
        })
    }

    /// Attempts to deserialize `self.beacon_state`, returning an error if it's missing or invalid.
    pub fn beacon_state<E: EthSpec>(&self) -> Result<BeaconState<E>, String> {
        let spec = self.chain_spec::<E>()?;
        let genesis_state_bytes = self
            .genesis_state_bytes
            .as_ref()
            .ok_or("Genesis state is unknown")?;

        BeaconState::from_ssz_bytes(genesis_state_bytes, &spec)
            .map_err(|e| format!("Genesis state SSZ bytes are invalid: {:?}", e))
    }

    /// Write the files to the directory.
    ///
    /// Overwrites files if specified to do so.
    pub fn write_to_file(&self, base_dir: PathBuf, overwrite: bool) -> Result<(), String> {
        if base_dir.exists() && !overwrite {
            return Err("Network directory already exists".to_string());
        }

        self.force_write_to_file(base_dir)
    }

    /// Write the files to the directory, even if the directory already exists.
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
                        let no_doc_header = if let Some(stripped) = yaml.strip_prefix("---\n") {
                            stripped
                        } else {
                            &yaml
                        };

                        file.write_all(no_doc_header.as_bytes())
                            .map_err(|e| format!("Unable to write {}: {:?}", $file, e))
                    })?;
            };
        }

        write_to_yaml_file!(DEPLOY_BLOCK_FILE, self.deposit_contract_deploy_block);

        if let Some(boot_enr) = &self.boot_enr {
            write_to_yaml_file!(BOOT_ENR_FILE, boot_enr);
        }

        write_to_yaml_file!(BASE_CONFIG_FILE, &self.config);

        // The genesis state is a special case because it uses SSZ, not YAML.
        if let Some(genesis_state_bytes) = &self.genesis_state_bytes {
            let file = base_dir.join(GENESIS_STATE_FILE);

            File::create(&file)
                .map_err(|e| format!("Unable to create {:?}: {:?}", file, e))
                .and_then(|mut file| {
                    file.write_all(genesis_state_bytes)
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

        let deposit_contract_deploy_block = load_from_file!(DEPLOY_BLOCK_FILE);
        let boot_enr = optional_load_from_file!(BOOT_ENR_FILE);
        let config = load_from_file!(BASE_CONFIG_FILE);

        // The genesis state is a special case because it uses SSZ, not YAML.
        let genesis_file_path = base_dir.join(GENESIS_STATE_FILE);
        let genesis_state_bytes = if genesis_file_path.exists() {
            let mut bytes = vec![];
            File::open(&genesis_file_path)
                .map_err(|e| format!("Unable to open {:?}: {:?}", genesis_file_path, e))
                .and_then(|mut file| {
                    file.read_to_end(&mut bytes)
                        .map_err(|e| format!("Unable to read {:?}: {:?}", file, e))
                })?;

            Some(bytes).filter(|bytes| !bytes.is_empty())
        } else {
            None
        };

        Ok(Self {
            deposit_contract_deploy_block,
            boot_enr,
            genesis_state_bytes,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;
    use tempfile::Builder as TempBuilder;
    use types::{Config, Eth1Data, Hash256, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn default_network_exists() {
        assert!(HARDCODED_NET_NAMES.contains(&DEFAULT_HARDCODED_NETWORK));
    }

    #[test]
    fn hardcoded_testnet_names() {
        assert_eq!(HARDCODED_NET_NAMES.len(), HARDCODED_NETS.len());
        for (name, net) in HARDCODED_NET_NAMES.iter().zip(HARDCODED_NETS.iter()) {
            assert_eq!(name, &net.name);
        }
    }

    #[test]
    fn mainnet_config_eq_chain_spec() {
        let config = Eth2NetworkConfig::from_hardcoded_net(&MAINNET).unwrap();
        let spec = ChainSpec::mainnet();
        assert_eq!(spec, config.chain_spec::<E>().unwrap());
    }

    #[test]
    fn mainnet_genesis_state() {
        let config = Eth2NetworkConfig::from_hardcoded_net(&MAINNET).unwrap();
        config.beacon_state::<E>().expect("beacon state can decode");
    }

    #[test]
    fn hard_coded_nets_work() {
        for net in HARDCODED_NETS {
            let config = Eth2NetworkConfig::from_hardcoded_net(net)
                .unwrap_or_else(|_| panic!("{:?}", net.name));

            // Ensure we can parse the YAML config to a chain spec.
            config.chain_spec::<MainnetEthSpec>().unwrap();

            assert_eq!(
                config.genesis_state_bytes.is_some(),
                net.genesis_is_known,
                "{:?}",
                net.name
            );
        }
    }

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
        let config = Config::from_chain_spec::<E>(spec);

        do_test::<E>(boot_enr, genesis_state, config.clone());
        do_test::<E>(None, None, config);
    }

    fn do_test<E: EthSpec>(
        boot_enr: Option<Vec<Enr<CombinedKey>>>,
        genesis_state: Option<BeaconState<E>>,
        config: Config,
    ) {
        let temp_dir = TempBuilder::new()
            .prefix("eth2_testnet_test")
            .tempdir()
            .expect("should create temp dir");
        let base_dir = temp_dir.path().join("my_testnet");
        let deposit_contract_deploy_block = 42;

        let testnet: Eth2NetworkConfig = Eth2NetworkConfig {
            deposit_contract_deploy_block,
            boot_enr,
            genesis_state_bytes: genesis_state.as_ref().map(Encode::as_ssz_bytes),
            config,
        };

        testnet
            .write_to_file(base_dir.clone(), false)
            .expect("should write to file");

        let decoded = Eth2NetworkConfig::load(base_dir).expect("should load struct");

        assert_eq!(testnet, decoded, "should decode as encoded");
    }
}
