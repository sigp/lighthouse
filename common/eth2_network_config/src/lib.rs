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

use bytes::Bytes;
use discv5::enr::{CombinedKey, Enr};
use eth2_config::{instantiate_hardcoded_nets, HardcodedNet};
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{Client, Error};
use sensitive_url::SensitiveUrl;
use sha2::{Digest, Sha256};
use slog::{info, warn, Logger};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use types::{BeaconState, ChainSpec, Config, Epoch, EthSpec, EthSpecId, Hash256};
use url::Url;

pub use eth2_config::GenesisStateSource;

pub const DEPLOY_BLOCK_FILE: &str = "deposit_contract_block.txt";
pub const BOOT_ENR_FILE: &str = "boot_enr.yaml";
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub const BASE_CONFIG_FILE: &str = "config.yaml";

// Creates definitions for:
//
// - Each of the `HardcodedNet` values (e.g., `MAINNET`, `HOLESKY`, etc).
// - `HARDCODED_NETS: &[HardcodedNet]`
// - `HARDCODED_NET_NAMES: &[&'static str]`
instantiate_hardcoded_nets!(eth2_config);

pub const DEFAULT_HARDCODED_NETWORK: &str = "mainnet";

/// Contains the bytes from the trusted setup json.
/// The mainnet trusted setup is also reused in testnets.
///
/// This is done to ensure that testnets also inherit the high security and
/// randomness of the mainnet kzg trusted setup ceremony.
///
/// Note: The trusted setup for both mainnet and minimal presets are the same.
pub const TRUSTED_SETUP_BYTES: &[u8] =
    include_bytes!("../built_in_network_configs/trusted_setup.json");

/// Returns `Some(TrustedSetup)` if the deneb fork epoch is set and `None` otherwise.
///
/// Returns an error if the trusted setup parsing failed.
fn get_trusted_setup_from_config(config: &Config) -> Option<Vec<u8>> {
    config
        .deneb_fork_epoch
        .filter(|epoch| epoch.value != Epoch::max_value())
        .map(|_| TRUSTED_SETUP_BYTES.to_vec())
}

/// A simple slice-or-vec enum to avoid cloning the beacon state bytes in the
/// binary whilst also supporting loading them from a file at runtime.
#[derive(Clone, PartialEq, Debug)]
pub enum GenesisStateBytes {
    Slice(&'static [u8]),
    Vec(Vec<u8>),
}

impl AsRef<[u8]> for GenesisStateBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            GenesisStateBytes::Slice(slice) => slice,
            GenesisStateBytes::Vec(vec) => vec.as_ref(),
        }
    }
}

impl From<&'static [u8]> for GenesisStateBytes {
    fn from(slice: &'static [u8]) -> Self {
        GenesisStateBytes::Slice(slice)
    }
}

impl From<Vec<u8>> for GenesisStateBytes {
    fn from(vec: Vec<u8>) -> Self {
        GenesisStateBytes::Vec(vec)
    }
}

/// Specifies an Eth2 network.
///
/// See the crate-level documentation for more details.
#[derive(Clone, PartialEq, Debug)]
pub struct Eth2NetworkConfig {
    /// Note: instead of the block where the contract is deployed, it is acceptable to set this
    /// value to be the block number where the first deposit occurs.
    pub deposit_contract_deploy_block: u64,
    pub boot_enr: Option<Vec<Enr<CombinedKey>>>,
    pub genesis_state_source: GenesisStateSource,
    pub genesis_state_bytes: Option<GenesisStateBytes>,
    pub config: Config,
    pub kzg_trusted_setup: Option<Vec<u8>>,
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
        let config: Config = serde_yaml::from_reader(net.config)
            .map_err(|e| format!("Unable to parse yaml config: {:?}", e))?;
        let kzg_trusted_setup = get_trusted_setup_from_config(&config);
        Ok(Self {
            deposit_contract_deploy_block: serde_yaml::from_reader(net.deploy_block)
                .map_err(|e| format!("Unable to parse deploy block: {:?}", e))?,
            boot_enr: Some(
                serde_yaml::from_reader(net.boot_enr)
                    .map_err(|e| format!("Unable to parse boot enr: {:?}", e))?,
            ),
            genesis_state_source: net.genesis_state_source,
            genesis_state_bytes: Some(net.genesis_state_bytes)
                .filter(|bytes| !bytes.is_empty())
                .map(Into::into),
            config,
            kzg_trusted_setup,
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
    pub fn genesis_state_is_known(&self) -> bool {
        self.genesis_state_source != GenesisStateSource::Unknown
    }

    /// The `genesis_validators_root` of the genesis state.
    pub fn genesis_validators_root<E: EthSpec>(&self) -> Result<Option<Hash256>, String> {
        if let GenesisStateSource::Url {
            genesis_validators_root,
            ..
        } = self.genesis_state_source
        {
            Hash256::from_str(genesis_validators_root)
                .map(Option::Some)
                .map_err(|e| {
                    format!(
                        "Unable to parse genesis state genesis_validators_root: {:?}",
                        e
                    )
                })
        } else {
            self.get_genesis_state_from_bytes::<E>()
                .map(|state| Some(state.genesis_validators_root()))
        }
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
    ///
    /// If the genesis state is configured to be downloaded from a URL, then the
    /// `genesis_state_url` will override the built-in list of download URLs.
    pub async fn genesis_state<E: EthSpec>(
        &self,
        genesis_state_url: Option<&str>,
        timeout: Duration,
        log: &Logger,
    ) -> Result<Option<BeaconState<E>>, String> {
        let spec = self.chain_spec::<E>()?;
        match &self.genesis_state_source {
            GenesisStateSource::Unknown => Ok(None),
            GenesisStateSource::IncludedBytes => {
                let state = self.get_genesis_state_from_bytes()?;
                Ok(Some(state))
            }
            GenesisStateSource::Url {
                urls: built_in_urls,
                checksum,
                genesis_validators_root,
            } => {
                let checksum = Hash256::from_str(checksum).map_err(|e| {
                    format!("Unable to parse genesis state bytes checksum: {:?}", e)
                })?;
                let bytes = if let Some(specified_url) = genesis_state_url {
                    download_genesis_state(&[specified_url], timeout, checksum, log).await
                } else {
                    download_genesis_state(built_in_urls, timeout, checksum, log).await
                }?;
                let state = BeaconState::from_ssz_bytes(bytes.as_ref(), &spec).map_err(|e| {
                    format!("Downloaded genesis state SSZ bytes are invalid: {:?}", e)
                })?;

                let genesis_validators_root =
                    Hash256::from_str(genesis_validators_root).map_err(|e| {
                        format!(
                            "Unable to parse genesis state genesis_validators_root: {:?}",
                            e
                        )
                    })?;
                if state.genesis_validators_root() != genesis_validators_root {
                    return Err(format!(
                        "Downloaded genesis validators root {:?} does not match expected {:?}",
                        state.genesis_validators_root(),
                        genesis_validators_root
                    ));
                }

                Ok(Some(state))
            }
        }
    }

    fn get_genesis_state_from_bytes<E: EthSpec>(&self) -> Result<BeaconState<E>, String> {
        let spec = self.chain_spec::<E>()?;
        self.genesis_state_bytes
            .as_ref()
            .map(|bytes| {
                BeaconState::from_ssz_bytes(bytes.as_ref(), &spec)
                    .map_err(|e| format!("Built-in genesis state SSZ bytes are invalid: {:?}", e))
            })
            .ok_or("Genesis state bytes missing from Eth2NetworkConfig")?
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
                    file.write_all(genesis_state_bytes.as_ref())
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
                    })?
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
        let (genesis_state_bytes, genesis_state_source) = if genesis_file_path.exists() {
            let mut bytes = vec![];
            File::open(&genesis_file_path)
                .map_err(|e| format!("Unable to open {:?}: {:?}", genesis_file_path, e))
                .and_then(|mut file| {
                    file.read_to_end(&mut bytes)
                        .map_err(|e| format!("Unable to read {:?}: {:?}", file, e))
                })?;

            let state = Some(bytes).filter(|bytes| !bytes.is_empty());
            let genesis_state_source = if state.is_some() {
                GenesisStateSource::IncludedBytes
            } else {
                GenesisStateSource::Unknown
            };
            (state, genesis_state_source)
        } else {
            (None, GenesisStateSource::Unknown)
        };

        let kzg_trusted_setup = get_trusted_setup_from_config(&config);

        Ok(Self {
            deposit_contract_deploy_block,
            boot_enr,
            genesis_state_source,
            genesis_state_bytes: genesis_state_bytes.map(Into::into),
            config,
            kzg_trusted_setup,
        })
    }
}

/// Try to download a genesis state from each of the `urls` in the order they
/// are defined. Return `Ok` if any url returns a response that matches the
/// given `checksum`.
async fn download_genesis_state(
    urls: &[&str],
    timeout: Duration,
    checksum: Hash256,
    log: &Logger,
) -> Result<Vec<u8>, String> {
    if urls.is_empty() {
        return Err(
            "The genesis state is not present in the binary and there are no known download URLs. \
            Please use --checkpoint-sync-url or --genesis-state-url."
                .to_string(),
        );
    }

    let mut errors = vec![];
    for url in urls {
        // URLs are always expected to be the base URL of a server that supports
        // the beacon-API.
        let url = parse_state_download_url(url)?;
        let redacted_url = SensitiveUrl::new(url.clone())
            .map(|url| url.to_string())
            .unwrap_or_else(|_| "<REDACTED>".to_string());

        info!(
            log,
            "Downloading genesis state";
            "server" => &redacted_url,
            "timeout" => ?timeout,
            "info" => "this may take some time on testnets with large validator counts"
        );

        let client = Client::new();
        let response = get_state_bytes(timeout, url, client).await;

        match response {
            Ok(bytes) => {
                // Check the server response against our local checksum.
                if Sha256::digest(bytes.as_ref())[..] == checksum[..] {
                    return Ok(bytes.into());
                } else {
                    warn!(
                        log,
                        "Genesis state download failed";
                        "server" => &redacted_url,
                        "timeout" => ?timeout,
                    );
                    errors.push(format!(
                        "Response from {} did not match local checksum",
                        redacted_url
                    ))
                }
            }
            Err(e) => errors.push(PrettyReqwestError::from(e).to_string()),
        }
    }
    Err(format!(
        "Unable to download a genesis state from {} source(s): {}",
        errors.len(),
        errors.join(",")
    ))
}

async fn get_state_bytes(timeout: Duration, url: Url, client: Client) -> Result<Bytes, Error> {
    client
        .get(url)
        .header("Accept", "application/octet-stream")
        .timeout(timeout)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await
}

/// Parses the `url` and joins the necessary state download path.
fn parse_state_download_url(url: &str) -> Result<Url, String> {
    Url::parse(url)
        .map_err(|e| format!("Invalid genesis state URL: {:?}", e))?
        .join("eth/v2/debug/beacon/states/genesis")
        .map_err(|e| format!("Failed to append genesis state path to URL: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;
    use tempfile::Builder as TempBuilder;
    use types::{Eth1Data, GnosisEthSpec, MainnetEthSpec};

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
    fn gnosis_config_eq_chain_spec() {
        let config = Eth2NetworkConfig::from_hardcoded_net(&GNOSIS).unwrap();
        let spec = ChainSpec::gnosis();
        assert_eq!(spec, config.chain_spec::<GnosisEthSpec>().unwrap());
    }

    #[tokio::test]
    async fn mainnet_genesis_state() {
        let config = Eth2NetworkConfig::from_hardcoded_net(&MAINNET).unwrap();
        config
            .genesis_state::<E>(None, Duration::from_secs(1), &logging::test_logger())
            .await
            .expect("beacon state can decode");
    }

    #[test]
    fn hard_coded_nets_work() {
        for net in HARDCODED_NETS {
            let config = Eth2NetworkConfig::from_hardcoded_net(net)
                .unwrap_or_else(|e| panic!("{:?}: {:?}", net.name, e));

            // Ensure we can parse the YAML config to a chain spec.
            if config.config.preset_base == types::GNOSIS {
                config.chain_spec::<GnosisEthSpec>().unwrap();
            } else {
                config.chain_spec::<MainnetEthSpec>().unwrap();
            }

            assert_eq!(
                config.genesis_state_bytes.is_some(),
                net.genesis_state_source == GenesisStateSource::IncludedBytes,
                "{:?}",
                net.name
            );

            if let GenesisStateSource::Url {
                urls,
                checksum,
                genesis_validators_root,
            } = net.genesis_state_source
            {
                Hash256::from_str(checksum).expect("the checksum must be a valid 32-byte value");
                Hash256::from_str(genesis_validators_root)
                    .expect("the GVR must be a valid 32-byte value");
                for url in urls {
                    parse_state_download_url(url).expect("url must be valid");
                }
            }

            assert_eq!(config.config.config_name, Some(net.config_dir.to_string()));
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

        let genesis_state_source = if genesis_state.is_some() {
            GenesisStateSource::IncludedBytes
        } else {
            GenesisStateSource::Unknown
        };
        // With Deneb enabled by default we must set a trusted setup here.
        let kzg_trusted_setup = get_trusted_setup_from_config(&config).unwrap();

        let testnet = Eth2NetworkConfig {
            deposit_contract_deploy_block,
            boot_enr,
            genesis_state_source,
            genesis_state_bytes: genesis_state
                .as_ref()
                .map(Encode::as_ssz_bytes)
                .map(Into::into),
            config,
            kzg_trusted_setup: Some(kzg_trusted_setup),
        };

        testnet
            .write_to_file(base_dir.clone(), false)
            .expect("should write to file");

        let decoded = Eth2NetworkConfig::load(base_dir).expect("should load struct");

        assert_eq!(testnet, decoded, "should decode as encoded");
    }
}
