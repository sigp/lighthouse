use crate::process::SimProcess;
use crate::testnet::{Testnet, TestnetValidatorClient};
use crate::{BEACON_CMD, BOOT_NODE_CMD, DEFAULT_CONFIG_PATH, GANACHE_CMD, LCLI_CMD, VALIDATOR_CMD};
use clap_utils::flags::{
    BEACON_NODES_FLAG, DATADIR_FLAG, ENABLE_DOPPELGANGER_PROTECTION_FLAG, ENR_TCP_PORT_FLAG,
    ENR_UDP_PORT_FLAG, HTTP_PORT_FLAG, NETWORK_DIR_FLAG, PORT_FLAG,
};
use clap_utils::lcli_flags::*;
use clap_utils::{to_string_map, toml_value_to_string, TomlValue};
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use eth2::types::Slot;
use fs_extra::dir::CopyOptions;
use sensitive_url::SensitiveUrl;
use serde_derive::{Deserialize, Serialize};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread, time};

pub type TomlConfig = Option<HashMap<String, TomlValue>>;
pub type Config = HashMap<String, String>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct GlobalTomlConfig {
    pub spec: TomlValue,
    pub validator_count: Option<TomlValue>,
    pub beacon_count: Option<TomlValue>,
    pub datadir: TomlValue,
    pub doppelganger_count: Option<TomlValue>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LcliConfig {
    pub deploy_deposit_contract: TomlConfig,
    pub new_testnet: TomlConfig,
    pub insecure_validators: TomlConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IntegrationTestConfig {
    pub global: GlobalTomlConfig,
    pub ganache: TomlConfig,
    pub lcli: LcliConfig,
    pub boot_node: TomlConfig,
    pub beacon: HashMap<String, TomlConfig>,
    pub validator: HashMap<String, TomlConfig>,
    pub lighthouse_bin_location: Option<PathBuf>,
}

impl IntegrationTestConfig {
    pub fn new(lighthouse_bin: &str) -> Result<Self, String> {
        crate::parse_file_config_maps(DEFAULT_CONFIG_PATH)?
            .set_bin_location(lighthouse_bin)
            .process_global_config()
    }

    fn set_bin_location(mut self, lighthouse_bin: &str) -> Self {
        let path = lighthouse_bin
            .parse::<PathBuf>()
            .expect("valid lighthouse binary location required");
        self.lighthouse_bin_location = Some(path);
        self
    }

    fn process_global_config(mut self) -> Result<Self, String> {
        let node_count = self
            .global
            .beacon_count
            .as_ref()
            .unwrap_or(&TomlValue::Integer(0))
            .as_integer()
            .unwrap() as usize;
        let validator_count = self
            .global
            .validator_count
            .clone()
            .unwrap_or(TomlValue::Integer(0));
        let doppelganger_count = self
            .global
            .doppelganger_count
            .as_ref()
            .unwrap_or(&TomlValue::Integer(0))
            .as_integer()
            .unwrap() as usize;

        let (testnet_dir, bootnode_dir) = (
            TomlValue::String(format!("{}/testnet", self.global.datadir.as_str().unwrap())),
            TomlValue::String(format!(
                "{}/bootnode",
                self.global.datadir.as_str().unwrap()
            )),
        );

        let len = self.validator.len();
        if let Some(config) = self.validator.get_mut("default") {
            let mut i = 0;
            let config_clone = config.clone();
            while i < node_count - len {
                i = i + 1;
                self.validator
                    .insert(format!("default-{}", i), config_clone.clone());
            }
        } else if self.validator.len() != node_count {
            return Err(
                "defaults need to be defined if all nodes are not explicitly defined".to_string(),
            );
        }

        let len = self.beacon.len();
        if let Some(config) = self.beacon.get_mut("default") {
            let mut i = 0;
            let config_clone = config.clone();
            while i < node_count - len {
                i = i + 1;
                self.beacon
                    .insert(format!("default-{}", i), config_clone.clone());
            }
        } else if self.beacon.len() != node_count {
            return Err(
                "defaults need to be defined if all nodes are not explicitly defined".to_string(),
            );
        }

        if let Some(config) = self.lcli.new_testnet.as_mut() {
            config.insert(VALIDATOR_COUNT_FLAG.to_string(), validator_count.clone());
            config.insert(
                MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG.to_string(),
                validator_count.clone(),
            );
            config.insert(SPEC_FLAG.to_string(), self.global.spec.clone());
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
            config.insert(BASE_DIR_FLAG.to_string(), self.global.datadir.clone());
        }

        if let Some(config) = self.boot_node.as_mut() {
            config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
            config.insert(NETWORK_DIR_FLAG.to_string(), bootnode_dir.clone());
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

    pub fn start_testnet(&mut self) -> Result<Testnet, String> {
        // cleanup previous testnet files
        if let Some(dir) = self.global.datadir.as_str() {
            let path = dir.parse::<Path>()?;
            if path.exists() {
                fs::remove_dir_all(dir).map_err(|e| format!("failed to remove datadir: {}", e))?;
            }
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
                .expect("lighthouse bin location required"),
        })
    }

    fn start_ganache(&mut self) -> Result<SimProcess, String> {
        let config = to_string_map(
            self.ganache
                .take()
                .ok_or("unable to parse ganache config")?,
            toml_value_to_string,
        )?;

        let mut process = SimProcess::new(GANACHE_CMD, config).spawn_no_wait();

        // Need to give ganache time to start up
        thread::sleep(time::Duration::from_secs(5));

        Ok(process)
    }

    fn setup_lcli(&mut self) -> Result<SystemTimeSlotClock, String> {
        let deposit_config = self
            .lcli
            .deploy_deposit_contract
            .take()
            .ok_or("unable to parse deploy contract config")?;
        self.run_lcli_for_config(LCLI_CMD, DEPLOY_DEPOSIT_CONTRACT_CMD, deposit_config)?;

        let mut testnet_config = self
            .lcli
            .new_testnet
            .take()
            .ok_or("unable to parse new testnet config")?;

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
                    .expect("invalid genesis delay")
                    .checked_add(Duration::from_secs(genesis_delay as u64))
                    .ok_or("invalid genesis delay")?;

                let slot_duration = Duration::from_secs(seconds_per_slot as u64);
                (genesis_time, slot_duration)
            } else {
                return Err(format!(
                    "{} and {} must be configured",
                    GENESIS_DELAY_FLAG, SECONDS_PER_SLOT_FLAG
                ));
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
            .ok_or("unable to parse insecure validator config")?;

        let node_count = insecure_val_config
            .get(NODE_COUNT_FLAG)
            .as_ref()
            .unwrap()
            .as_integer()
            .unwrap();
        let base_dir = insecure_val_config
            .get(BASE_DIR_FLAG)
            .as_ref()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
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
            fs::create_dir(new.as_str()).unwrap();
            let mut copy_options = CopyOptions::default();
            copy_options.content_only = true;
            fs_extra::dir::copy(old.as_str(), new.as_str(), &copy_options)
                .map_err(|e| format!("Old location: {}, new location: {}, {}", old, new, e))?;
        }

        let slot_clock = SystemTimeSlotClock::new(Slot::new(0), genesis_duration, slot_duration);

        Ok(slot_clock)
    }

    fn run_lcli_for_config(
        &mut self,
        command: &str,
        subcommand: &str,
        config: HashMap<String, TomlValue>,
    ) -> Result<(), String> {
        let config = to_string_map(config, toml_value_to_string)?;

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

        let app = lcli::new_app()
            .try_get_matches_from(config_vec)
            .map_err(|e| format!("{}", e))?;
        lcli::run(&app)
    }

    fn spawn_bootnode(&mut self) -> Result<SimProcess, String> {
        let config = to_string_map(
            self.boot_node
                .take()
                .ok_or("unable to parse boot node config")?,
            toml_value_to_string,
        )?;

        let mut process = SimProcess::new_lighthouse_process(
            self.lighthouse_bin_location
                .as_ref()
                .expect("lighthouse bin location required"),
            BOOT_NODE_CMD,
            &config,
        )
        .spawn_no_wait();

        // Need to give boot node time to start up
        thread::sleep(time::Duration::from_secs(5));

        Ok(process)
    }

    fn spawn_beacon_nodes(&mut self) -> Result<Vec<SimProcess>, String> {
        let mut processes = vec![];

        for (i, (name, config)) in self.beacon.iter_mut().enumerate() {
            let index = i + 1;

            let mut config = to_string_map(
                config
                    .take()
                    .ok_or(format!("unable to parse {} config", name))?,
                toml_value_to_string,
            )?;
            if name.starts_with("default") {
                config.insert(
                    DATADIR_FLAG.to_string(),
                    format!("{}/node_{}", self.global.datadir.as_str().unwrap(), index),
                );
                let discovery_port = format!("9{}00", index);
                config.insert(PORT_FLAG.to_string(), discovery_port.clone());
                config.insert(ENR_UDP_PORT_FLAG.to_string(), discovery_port.clone());
                config.insert(ENR_TCP_PORT_FLAG.to_string(), discovery_port);
                config.insert(HTTP_PORT_FLAG.to_string(), format!("5{}52", index));
            } else {
                config.entry(DATADIR_FLAG.to_string()).or_insert(format!(
                    "{}/node_{}",
                    self.global.datadir.as_str().unwrap(),
                    index
                ));
                let discovery_port = format!("9{}00", index);
                config
                    .entry(PORT_FLAG.to_string())
                    .or_insert(discovery_port.clone());
                config
                    .entry(ENR_UDP_PORT_FLAG.to_string())
                    .or_insert(discovery_port.clone());
                config
                    .entry(ENR_TCP_PORT_FLAG.to_string())
                    .or_insert(discovery_port);
                config
                    .entry(HTTP_PORT_FLAG.to_string())
                    .or_insert(format!("5{}52", index));
            }
            let process = SimProcess::new_lighthouse_process(
                self.lighthouse_bin_location
                    .as_ref()
                    .expect("lighthouse bin location required"),
                BEACON_CMD,
                &config,
            )
            .spawn_no_wait();
            processes.push(process);
        }

        Ok(processes)
    }

    fn spawn_validator_clients(
        &mut self,
    ) -> Result<(Vec<TestnetValidatorClient>, Vec<Config>), String> {
        let mut validator_clients = vec![];
        let mut delayed_start_configs = vec![];

        //TODO: allow config for delayed starting of non-doppelganger VC's

        let len = self.validator.len();

        for (i, (name, config)) in self.validator.iter_mut().enumerate() {
            let index = i + 1;
            let mut config = to_string_map(
                config
                    .take()
                    .ok_or(format!("unable to parse {} config", name))?,
                toml_value_to_string,
            )?;
            // if name starts with default, always insert incremental config, otherwise only insert it if it doesn't exist
            if name.starts_with("default") {
                config.insert(
                    DATADIR_FLAG.to_string(),
                    format!("{}/node_{}", self.global.datadir.as_str().unwrap(), index),
                );
                config.insert(
                    BEACON_NODES_FLAG.to_string(),
                    format!("http://localhost:5{}52", index),
                );
            } else {
                config.entry(DATADIR_FLAG.to_string()).or_insert(format!(
                    "{}/node_{}",
                    self.global.datadir.as_str().unwrap(),
                    index
                ));
                config
                    .entry(BEACON_NODES_FLAG.to_string())
                    .or_insert(format!("localhost:5{}52", index));
            }

            let doppelganger_count = self
                .global
                .doppelganger_count
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
            } else {
                validator_clients.push(spawn_validator(
                    self.lighthouse_bin_location
                        .as_ref()
                        .expect("lighthouse bin location required"),
                    config,
                )?);
            }
        }

        Ok((validator_clients, delayed_start_configs))
    }
}

pub(crate) fn spawn_validator(
    lighthouse_bin: &Path,
    config: HashMap<String, String>,
) -> Result<TestnetValidatorClient, String> {
    let process =
        SimProcess::new_lighthouse_process(lighthouse_bin, VALIDATOR_CMD, &config).spawn_no_wait();

    // sleep to wait for API key creation.
    thread::sleep(Duration::from_secs(10));

    // API secret required for the VC API.
    if let (Some(datadir), Some(url)) = (
        config.get(DATADIR_FLAG).as_ref(),
        config.get(BEACON_NODES_FLAG).as_ref(),
    ) {
        let token_path = format!("{}{}", datadir, "/validators/api-token.txt").parse::<Path>()?;
        let secret = fs::read_to_string(token_path).expect("should read API token from file");
        let http_client = ValidatorClientHttpClient::new(
            SensitiveUrl::parse(url).expect("should create HTTP client"),
            secret,
        )
        .expect("should create HTTP client");

        let vc = TestnetValidatorClient {
            process,
            config,
            http_client,
        };
        Ok(vc)
    } else {
        Err("invalid config".to_string())
    }
}
