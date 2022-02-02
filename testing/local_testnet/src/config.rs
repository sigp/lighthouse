use crate::process::{ProcessError, TestnetProcess};
use crate::testnet::{Testnet, TestnetBeaconNode, TestnetValidatorClient};
use crate::{
    BEACON_CMD, BOOT_NODE_CMD, DEFAULT_CONFIG, DEFAULT_KEY, GANACHE_CMD, LCLI_CMD, VALIDATOR_CMD,
};
use clap_utils::flags::{
    BEACON_NODES_FLAG, DATADIR_FLAG, ENABLE_DOPPELGANGER_PROTECTION_FLAG, ENR_TCP_PORT_FLAG,
    ENR_UDP_PORT_FLAG, HTTP_ADDRESS_FLAG, HTTP_PORT_FLAG, NETWORK_DIR_FLAG, PORT_FLAG,
};
use clap_utils::lcli_flags::*;
use clap_utils::{to_string_map, toml_value_to_string, TomlValue};
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use eth2::types::Slot;
use eth2::{BeaconNodeHttpClient, Timeouts};
use fs_extra::dir::CopyOptions;
use sensitive_url::{SensitiveError, SensitiveUrl};
use serde_derive::{Deserialize, Serialize};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::format;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread, time};

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("unable to parse config")]
    FileParse(#[from] Infallible),
    #[error("defaults need to be defined if all nodes are not explicitly defined")]
    UndefinedBeacons,
    #[error("defaults need to be defined if all nodes are not explicitly defined")]
    UndefinedValidators,
    #[error("config file must have extension `.toml`")]
    InvalidExtension,
    #[error("unable to deserialize TOML")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("unable to read TOML file")]
    IO(#[from] std::io::Error),
    #[error("Old location: {old_location}, new location: {new_location}, {error}")]
    FileCopy {
        old_location: String,
        new_location: String,
        error: fs_extra::error::Error,
    },
    #[error("lighthouse bin location required")]
    MissingLighthouseBinary,
    #[error("invalid genesis delay")]
    InvalidGenesisDelay,
    #[error("failed to remove datadir {0}")]
    Cleanup(std::io::Error),
    #[error("{0}")]
    TomlTransform(String),
    #[error("{0}")]
    Lcli(String),
    #[error("unable to match arguments")]
    Clap(#[from] lcli::ClapError),
    #[error("expected config {0}")]
    ConfigNotFound(&'static str),
    #[error("missing config fields {0:?}")]
    MissingFields(Vec<&'static str>),
    #[error("unable to create HTTP client: {0:?}")]
    ValidatorHTTPClient(eth2::Error),
    #[error("cannot parse URL: {0:?}")]
    UrlParse(SensitiveError),
    #[error("could not spawn process")]
    Process(#[from] ProcessError),
}

pub type TomlConfig = Option<HashMap<String, TomlValue>>;
pub type Config = HashMap<String, String>;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct GlobalTomlConfig {
    pub spec: Option<TomlValue>,
    pub validator_count: Option<TomlValue>,
    pub beacon_count: Option<TomlValue>,
    pub datadir: Option<TomlValue>,
    pub doppelganger_count: Option<TomlValue>,
    pub delayed_validator_count: Option<TomlValue>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct LcliConfig {
    pub deploy_deposit_contract: TomlConfig,
    pub new_testnet: TomlConfig,
    pub insecure_validators: TomlConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IntegrationTestConfig {
    pub global: GlobalTomlConfig,
    pub ganache: TomlConfig,
    pub lcli: LcliConfig,
    pub boot_node: TomlConfig,
    pub beacon: HashMap<String, TomlConfig>,
    pub validator: HashMap<String, TomlConfig>,
    pub lighthouse_bin_location: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OptionalIntegrationTestConfig {
    pub global: Option<GlobalTomlConfig>,
    pub ganache: Option<TomlConfig>,
    pub lcli: Option<LcliConfig>,
    pub boot_node: Option<TomlConfig>,
    pub beacon: Option<HashMap<String, TomlConfig>>,
    pub validator: Option<HashMap<String, TomlConfig>>,
    pub lighthouse_bin_location: Option<PathBuf>,
}

impl OptionalIntegrationTestConfig {
    fn into_required(mut self, default: IntegrationTestConfig) -> IntegrationTestConfig {
        IntegrationTestConfig {
            global: self.global.unwrap_or(default.global),
            ganache: self.ganache.unwrap_or(default.ganache),
            lcli: self.lcli.unwrap_or(default.lcli),
            boot_node: self.boot_node.unwrap_or(default.boot_node),
            beacon: self.beacon.unwrap_or(default.beacon),
            validator: self.validator.unwrap_or(default.validator),
            lighthouse_bin_location: self.lighthouse_bin_location,
        }
    }
}

impl IntegrationTestConfig {
    fn merge(mut self, default: IntegrationTestConfig) -> Self {
        // Merge TOML configs
        self.beacon.get_mut(DEFAULT_KEY).map(|this| {
            merge(
                this,
                default
                    .beacon
                    .get(DEFAULT_KEY)
                    .expect("default beacon config required"),
            )
        });
        self.validator.get_mut(DEFAULT_KEY).map(|this| {
            merge(
                this,
                default
                    .validator
                    .get(DEFAULT_KEY)
                    .expect("default beacon config required"),
            )
        });
        merge(&mut self.ganache, &default.ganache);
        merge(&mut self.boot_node, &default.boot_node);
        Self {
            global: self.global.merge(default.global),
            ganache: self.ganache,
            lcli: self.lcli.merge(default.lcli),
            boot_node: self.boot_node,
            beacon: self.beacon,
            validator: self.validator,
            lighthouse_bin_location: self
                .lighthouse_bin_location
                .or(default.lighthouse_bin_location),
        }
    }
}

impl GlobalTomlConfig {
    fn merge(self, default: GlobalTomlConfig) -> Self {
        Self {
            spec: self.spec.or(default.spec),
            validator_count: self.validator_count.or(default.validator_count),
            beacon_count: self.beacon_count.or(default.beacon_count),
            datadir: self.datadir.or(default.datadir),
            doppelganger_count: self.doppelganger_count.or(default.doppelganger_count),
            delayed_validator_count: self
                .delayed_validator_count
                .or(default.delayed_validator_count),
        }
    }
}
impl LcliConfig {
    fn merge(mut self, default: LcliConfig) -> Self {
        merge(
            &mut self.deploy_deposit_contract,
            &default.deploy_deposit_contract,
        );
        merge(&mut self.new_testnet, &default.new_testnet);
        merge(&mut self.insecure_validators, &default.insecure_validators);
        Self {
            deploy_deposit_contract: self.deploy_deposit_contract,
            new_testnet: self.new_testnet,
            insecure_validators: self.insecure_validators,
        }
    }
}

fn merge(this: &mut TomlConfig, that: &TomlConfig) {
    if let Some(config) = this {
        for (k, v) in that.as_ref().expect("default config must exist") {
            config.entry(k.clone()).or_insert(v.clone());
        }
    } else {
        *this = that.clone();
    }
}

impl IntegrationTestConfig {
    pub fn new(lighthouse_bin: &str) -> Result<Self, ConfigError> {
        let default_config: IntegrationTestConfig =
            toml::from_str(DEFAULT_CONFIG).map_err(ConfigError::TomlDeserialize)?;
        default_config
            .set_bin_location(lighthouse_bin)?
            .process_global_config()
    }

    pub fn new_with_config(lighthouse_bin: &str, config_path: &str) -> Result<Self, ConfigError> {
        let default_config: IntegrationTestConfig =
            toml::from_str(DEFAULT_CONFIG).map_err(ConfigError::TomlDeserialize)?;
        let file_config =
            parse_file_config_maps(config_path)?.into_required(default_config.clone());
        let merged_config = file_config.merge(default_config);
        merged_config
            .set_bin_location(lighthouse_bin)?
            .process_global_config()
    }

    fn set_bin_location(mut self, lighthouse_bin: &str) -> Result<Self, ConfigError> {
        let path = lighthouse_bin.parse::<PathBuf>()?;
        self.lighthouse_bin_location = Some(path);
        Ok(self)
    }

    fn get_datadir(&self) -> Result<PathBuf, ConfigError> {
        self.global
            .datadir
            .as_ref()
            .map(TomlValue::as_str)
            .flatten()
            .map(PathBuf::from)
            .ok_or(ConfigError::MissingFields(vec![DATADIR_FLAG]))
    }

    /// This method ensures the global config is consistent across subcommands.
    fn process_global_config(mut self) -> Result<Self, ConfigError> {
        let node_count = self
            .global
            .beacon_count
            .as_ref()
            .map(TomlValue::as_integer)
            .flatten()
            .unwrap_or(0) as usize;
        let validator_count = self
            .global
            .validator_count
            .as_ref()
            .cloned()
            .unwrap_or(TomlValue::Integer(0));
        let doppelganger_count = self
            .global
            .doppelganger_count
            .as_ref()
            .map(TomlValue::as_integer)
            .flatten()
            .unwrap_or(0) as usize;

        let datadir = self.get_datadir()?;

        let (testnet_dir, bootnode_dir) = (
            TomlValue::String(datadir.join("testnet").to_str().unwrap().to_string()),
            TomlValue::String(datadir.join("bootnode").to_str().unwrap().to_string()),
        );

        let len = self.validator.len();
        if let Some(config) = self.validator.get_mut("default") {
            let mut i = 0;
            let config_clone = config.clone();
            while i < node_count - len {
                i += 1;
                self.validator
                    .insert(format!("default-{}", i), config_clone.clone());
            }
        } else if self.validator.len() != node_count {
            return Err(ConfigError::UndefinedValidators);
        }

        let len = self.beacon.len();
        if let Some(config) = self.beacon.get_mut("default") {
            let mut i = 0;
            let config_clone = config.clone();
            while i < node_count - len {
                i += 1;
                self.beacon
                    .insert(format!("default-{}", i), config_clone.clone());
            }
        } else if self.beacon.len() != node_count {
            return Err(ConfigError::UndefinedBeacons);
        }

        if let Some(config) = self.lcli.new_testnet.as_mut() {
            config.insert(VALIDATOR_COUNT_FLAG.to_string(), validator_count.clone());
            config.insert(
                MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG.to_string(),
                validator_count.clone(),
            );
            config.insert(
                SPEC_FLAG.to_string(),
                self.global
                    .spec
                    .as_ref()
                    .cloned()
                    .ok_or(ConfigError::MissingFields(vec![SPEC_FLAG]))?,
            );
            config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
            config.insert(BOOT_DIR_FLAG.to_string(), bootnode_dir.clone());
        }
        if let Some(config) = self.lcli.deploy_deposit_contract.as_mut() {
            config.insert(VALIDATOR_COUNT_FLAG.to_string(), validator_count.clone());
        }
        let len = self.validator.len();
        if let Some(config) = self.lcli.insecure_validators.as_mut() {
            config.insert(COUNT_FLAG.to_string(), validator_count);
            config.insert(
                NODE_COUNT_FLAG.to_string(),
                TomlValue::Integer((len - doppelganger_count) as i64),
            );
            config.insert(
                BASE_DIR_FLAG.to_string(),
                self.global
                    .datadir
                    .as_ref()
                    .ok_or(ConfigError::MissingFields(vec![DATADIR_FLAG]))?
                    .clone(),
            );
        }

        if let Some(config) = self.boot_node.as_mut() {
            config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
            config.insert(NETWORK_DIR_FLAG.to_string(), bootnode_dir);
        }
        for (_, config_opt) in self.beacon.iter_mut() {
            if let Some(config) = config_opt.as_mut() {
                config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
            }
        }
        for (_, config_opt) in self.validator.iter_mut() {
            if let Some(config) = config_opt.as_mut() {
                config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
            }
        }

        Ok(self)
    }

    pub fn start_testnet(&mut self) -> Result<Testnet, ConfigError> {
        // cleanup previous testnet files
        let dir = self.get_datadir()?;
        if dir.exists() {
            fs::remove_dir_all(dir).map_err(ConfigError::Cleanup)?;
        }

        let ganache = self.start_ganache()?;
        let slot_clock = self.setup_lcli()?;

        let bootnode = self.spawn_bootnode()?;
        let beacon_nodes = self.spawn_beacon_nodes()?;
        let (validator_clients, delayed_start_configs) = self.spawn_validator_clients()?;

        Ok(Testnet {
            ganache,
            bootnode,
            beacon_nodes,
            validator_clients,
            delayed_start_configs,
            slot_clock,
            global_config: self.global.clone(),
            lighthouse_bin_location: self
                .lighthouse_bin_location
                .take()
                .ok_or(ConfigError::MissingLighthouseBinary)?,
        })
    }

    fn start_ganache(&mut self) -> Result<TestnetProcess, ConfigError> {
        let config = to_string_map(
            self.ganache
                .take()
                .ok_or(ConfigError::ConfigNotFound(GANACHE_CMD))?,
            toml_value_to_string,
        )
        .map_err(ConfigError::TomlTransform)?;

        let process = TestnetProcess::new(GANACHE_CMD, config).spawn_no_wait()?;

        // Need to give ganache time to start up
        thread::sleep(time::Duration::from_secs(5));

        Ok(process)
    }

    fn setup_lcli(&mut self) -> Result<SystemTimeSlotClock, ConfigError> {
        let deposit_config = self
            .lcli
            .deploy_deposit_contract
            .take()
            .ok_or(ConfigError::ConfigNotFound(DEPLOY_DEPOSIT_CONTRACT_CMD))?;
        self.run_lcli_for_config(LCLI_CMD, DEPLOY_DEPOSIT_CONTRACT_CMD, deposit_config)?;

        let mut testnet_config = self
            .lcli
            .new_testnet
            .take()
            .ok_or(ConfigError::ConfigNotFound(NEW_TESTNET_CMD))?;

        // Setup genesis time
        let (genesis_duration, slot_duration) =
            if let (Some(genesis_delay), Some(seconds_per_slot)) = (
                testnet_config
                    .get(GENESIS_DELAY_FLAG)
                    .map(TomlValue::as_integer)
                    .map(Option::unwrap),
                testnet_config
                    .get(SECONDS_PER_SLOT_FLAG)
                    .map(TomlValue::as_integer)
                    .map(Option::unwrap),
            ) {
                let genesis_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("should calculate time since UNIX epoch")
                    .checked_add(Duration::from_secs(genesis_delay as u64))
                    .ok_or(ConfigError::InvalidGenesisDelay)?;

                let slot_duration = Duration::from_secs(seconds_per_slot as u64);
                (genesis_time, slot_duration)
            } else {
                return Err(ConfigError::MissingFields(vec![
                    GENESIS_DELAY_FLAG,
                    SECONDS_PER_SLOT_FLAG,
                ]));
            };
        testnet_config.insert(
            GENESIS_TIME_FLAG.to_string(),
            TomlValue::Integer(genesis_duration.as_secs() as i64),
        );

        self.run_lcli_for_config(LCLI_CMD, NEW_TESTNET_CMD, testnet_config)?;

        let insecure_val_config = self
            .lcli
            .insecure_validators
            .take()
            .ok_or(ConfigError::ConfigNotFound(INSECURE_VALIDATORS_CMD))?;

        let node_count = insecure_val_config
            .get(NODE_COUNT_FLAG)
            .map(TomlValue::as_integer)
            .flatten()
            .unwrap_or(0);
        let base_dir = insecure_val_config
            .get(BASE_DIR_FLAG)
            .map(TomlValue::as_str)
            .flatten()
            .map(ToString::to_string)
            .ok_or(ConfigError::MissingFields(vec![BASE_DIR_FLAG]))?;
        self.run_lcli_for_config(LCLI_CMD, INSECURE_VALIDATORS_CMD, insecure_val_config)?;

        let doppelganger_count = self
            .global
            .doppelganger_count
            .as_ref()
            .map(|v| v.as_integer())
            .flatten()
            .unwrap_or(0);
        for i in node_count + 1..=node_count + doppelganger_count {
            let old = format!("{}/node_1", base_dir);
            let new = format!("{}/node_{}", base_dir, i);
            fs::create_dir(new.as_str())?;
            let copy_options = CopyOptions {
                content_only: true,
                ..Default::default()
            };
            fs_extra::dir::copy(old.as_str(), new.as_str(), &copy_options).map_err(|e| {
                ConfigError::FileCopy {
                    old_location: old,
                    new_location: new,
                    error: e,
                }
            })?;
        }

        let slot_clock = SystemTimeSlotClock::new(Slot::new(0), genesis_duration, slot_duration);

        Ok(slot_clock)
    }

    fn run_lcli_for_config(
        &mut self,
        command: &str,
        subcommand: &str,
        config: HashMap<String, TomlValue>,
    ) -> Result<(), ConfigError> {
        let config =
            to_string_map(config, toml_value_to_string).map_err(ConfigError::TomlTransform)?;

        let mut config_vec: Vec<_> = config
            .into_iter()
            // Have to filter out "true" here for flags when calling `try_get_matches_from` later
            .flat_map(|(k, v)| {
                if v == "true" {
                    vec![format!("--{}", k)].into_iter()
                } else {
                    vec![format!("--{}", k), v].into_iter()
                }
            })
            .collect();
        config_vec.insert(0, subcommand.to_string());
        config_vec.insert(0, command.to_string());

        let app = lcli::new_app().try_get_matches_from(config_vec)?;
        lcli::run(&app).map_err(ConfigError::Lcli)
    }

    fn spawn_bootnode(&mut self) -> Result<TestnetProcess, ConfigError> {
        let config = to_string_map(
            self.boot_node
                .take()
                .ok_or(ConfigError::ConfigNotFound(BOOT_NODE_CMD))?,
            toml_value_to_string,
        )
        .map_err(ConfigError::TomlTransform)?;

        let process = TestnetProcess::new_lighthouse_process(
            self.lighthouse_bin_location
                .as_ref()
                .ok_or(ConfigError::MissingLighthouseBinary)?,
            BOOT_NODE_CMD,
            &config,
        )
        .spawn_no_wait()?;

        // Need to give boot node time to start up
        thread::sleep(time::Duration::from_secs(5));

        Ok(process)
    }

    fn spawn_beacon_nodes(&mut self) -> Result<Vec<TestnetBeaconNode>, ConfigError> {
        let datadir = self.get_datadir()?.to_str().unwrap().to_string();

        let mut processes = vec![];

        for (i, (name, config)) in self.beacon.iter_mut().enumerate() {
            let index = i + 1;

            let mut config = to_string_map(
                config
                    .take()
                    .ok_or(ConfigError::ConfigNotFound(BEACON_CMD))?,
                toml_value_to_string,
            )
            .map_err(ConfigError::TomlTransform)?;
            if name.starts_with("default") {
                config.insert(
                    DATADIR_FLAG.to_string(),
                    format!("{}/node_{}", datadir, index),
                );
                let discovery_port = format!("9{}00", index);
                config.insert(PORT_FLAG.to_string(), discovery_port.clone());
                config.insert(ENR_UDP_PORT_FLAG.to_string(), discovery_port.clone());
                config.insert(ENR_TCP_PORT_FLAG.to_string(), discovery_port);
                config.insert(HTTP_PORT_FLAG.to_string(), format!("5{}52", index));
            } else {
                config
                    .entry(DATADIR_FLAG.to_string())
                    .or_insert(format!("{}/node_{}", datadir, index));
                let discovery_port = format!("9{}00", index);
                config
                    .entry(PORT_FLAG.to_string())
                    .or_insert_with(|| discovery_port.clone());
                config
                    .entry(ENR_UDP_PORT_FLAG.to_string())
                    .or_insert_with(|| discovery_port.clone());
                config
                    .entry(ENR_TCP_PORT_FLAG.to_string())
                    .or_insert(discovery_port);
                config
                    .entry(HTTP_PORT_FLAG.to_string())
                    .or_insert_with(|| format!("5{}52", index));
            }

            processes.push(spawn_beacon_node(
                self.lighthouse_bin_location
                    .as_ref()
                    .ok_or(ConfigError::MissingLighthouseBinary)?,
                config,
            )?);
        }

        Ok(processes)
    }

    fn spawn_validator_clients(
        &mut self,
    ) -> Result<(Vec<TestnetValidatorClient>, Vec<Config>), ConfigError> {
        let mut validator_clients = vec![];
        let mut delayed_start_configs = vec![];
        let datadir = self.get_datadir()?.to_str().unwrap().to_string();

        //TODO: allow config for delayed starting of non-doppelganger VC's

        let len = self.validator.len();

        for (i, (name, config)) in self.validator.iter_mut().enumerate() {
            let index = i + 1;
            let mut config = to_string_map(
                config
                    .take()
                    .ok_or(ConfigError::ConfigNotFound(VALIDATOR_CMD))?,
                toml_value_to_string,
            )
            .map_err(ConfigError::TomlTransform)?;
            // if name starts with default, always insert incremental config, otherwise only insert it if it doesn't exist
            if name.starts_with("default") {
                config.insert(
                    DATADIR_FLAG.to_string(),
                    format!("{}/node_{}", datadir, index),
                );
                config.insert(
                    BEACON_NODES_FLAG.to_string(),
                    format!("http://localhost:5{}52", index),
                );
                config.insert(HTTP_PORT_FLAG.to_string(), format!("5{}62", index));
            } else {
                config
                    .entry(DATADIR_FLAG.to_string())
                    .or_insert(format!("{}/node_{}", datadir, index));
                config
                    .entry(BEACON_NODES_FLAG.to_string())
                    .or_insert(format!("localhost:5{}52", index));
                config
                    .entry(HTTP_PORT_FLAG.to_string())
                    .or_insert(format!("5{}62", index));
            }

            let doppelganger_count = self
                .global
                .doppelganger_count
                .as_ref()
                .map(|v| v.as_integer())
                .flatten()
                .unwrap_or(0);
            let delayed_start_count = self
                .global
                .delayed_validator_count
                .as_ref()
                .map(|v| v.as_integer())
                .flatten()
                .unwrap_or(0);
            if i >= len - doppelganger_count as usize {
                config.insert(
                    ENABLE_DOPPELGANGER_PROTECTION_FLAG.to_string(),
                    "true".to_string(),
                );
                config.insert(
                    BEACON_NODES_FLAG.to_string(),
                    "http://localhost:5152".to_string(),
                );
                delayed_start_configs.push(config);
            } else if i >= len - delayed_start_count as usize {
                delayed_start_configs.push(config);
            } else {
                validator_clients.push(spawn_validator(
                    self.lighthouse_bin_location
                        .as_ref()
                        .ok_or(ConfigError::MissingLighthouseBinary)?,
                    config,
                )?);
            }
        }

        Ok((validator_clients, delayed_start_configs))
    }
}

pub(crate) fn spawn_beacon_node(
    lighthouse_bin: &Path,
    config: HashMap<String, String>,
) -> Result<TestnetBeaconNode, ConfigError> {
    let process = TestnetProcess::new_lighthouse_process(lighthouse_bin, BEACON_CMD, &config)
        .spawn_no_wait()?;

    let default_address = "http://localhost".to_string();
    let http_address = config.get(HTTP_ADDRESS_FLAG).unwrap_or(&default_address);
    let http_port = config
        .get(HTTP_PORT_FLAG)
        .ok_or(ConfigError::MissingFields(vec![HTTP_PORT_FLAG]))?;
    let url = format!("{}:{}", http_address, http_port);

    let http_client = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(url.as_str()).map_err(ConfigError::UrlParse)?,
        Timeouts::set_all(Duration::from_secs(5)),
    );

    Ok(TestnetBeaconNode {
        process,
        config,
        http_client,
    })
}

pub(crate) fn spawn_validator(
    lighthouse_bin: &Path,
    config: HashMap<String, String>,
) -> Result<TestnetValidatorClient, ConfigError> {
    let process = TestnetProcess::new_lighthouse_process(lighthouse_bin, VALIDATOR_CMD, &config)
        .spawn_no_wait()?;

    // sleep to wait for API key creation.
    thread::sleep(Duration::from_secs(10));

    let default_address = "http://localhost".to_string();
    let http_address = config.get(HTTP_ADDRESS_FLAG).unwrap_or(&default_address);
    let http_port = config
        .get(HTTP_PORT_FLAG)
        .ok_or(ConfigError::MissingFields(vec![HTTP_PORT_FLAG]))?;
    let url = format!("{}:{}", http_address, http_port);

    // API secret required for the VC API.
    if let Some(datadir) = config.get(DATADIR_FLAG).as_ref() {
        let token_path = PathBuf::from(format!("{}/validators/api-token.txt", datadir));
        let secret = fs::read_to_string(token_path)?;

        let http_client = ValidatorClientHttpClient::new(
            SensitiveUrl::parse(&url).map_err(ConfigError::UrlParse)?,
            secret,
        )
        .map_err(ConfigError::ValidatorHTTPClient)?;

        let vc = TestnetValidatorClient {
            process,
            config,
            http_client,
        };
        Ok(vc)
    } else {
        Err(ConfigError::MissingFields(vec![
            DATADIR_FLAG,
            BEACON_NODES_FLAG,
        ]))
    }
}

fn parse_file_config_maps(file_name: &str) -> Result<OptionalIntegrationTestConfig, ConfigError> {
    if file_name.ends_with(".toml") {
        let toml = fs::read_to_string(file_name).map_err(ConfigError::IO)?;
        toml::from_str(toml.as_str()).map_err(ConfigError::TomlDeserialize)
    } else {
        Err(ConfigError::InvalidExtension)
    }
}
