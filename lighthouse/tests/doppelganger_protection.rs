use clap_utils::flags::{
    BEACON_NODES_FLAG, DATADIR_FLAG, HTTP_PORT_FLAG, NETWORK_DIR_FLAG, PORT_FLAG,
};
use clap_utils::lcli_flags::{
    BOOT_DIR_FLAG, DEPLOY_DEPOSIT_CONTRACT_CMD, GENESIS_DELAY_FLAG, GENESIS_TIME_FLAG,
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG, NEW_TESTNET_CMD, SPEC_FLAG, TESTNET_DIR_FLAG,
    VALIDATOR_COUNT_FLAG,
};
use clap_utils::{to_string_map, toml_value_to_string, TomlValue};
use lcli::new_app;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, io, thread, time};

const GANACHE_CMD: &str = "ganache-cli";
const LCLI_CMD: &str = "lcli";
const BEACON_CMD: &str = "beacon";
const VALIDATOR_CMD: &str = "validator";
const BOOT_NODE_CMD: &str = "boot_node";
const DEFAULT_CONFIG_PATH: &str = "./tests/doppelganger_config/default.toml";

pub type Config = Option<HashMap<String, TomlValue>>;

#[derive(Debug, Deserialize, Serialize)]
pub struct LcliConfig {
    #[serde(rename = "deploy-deposit-contract")]
    deploy_deposit_contract: Config,
    #[serde(rename = "new-testnet")]
    new_testnet: Config,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IntegrationTestConfig {
    global: Config,
    ganache: Config,
    lcli: LcliConfig,
    boot_node: Config,
    beacon: HashMap<String, Config>,
    validator: HashMap<String, Config>,
    datadir: Option<String>,
}

impl IntegrationTestConfig {
    pub fn new() -> Result<Self, String> {
        parse_file_config_maps(DEFAULT_CONFIG_PATH).and_then(|s| s.process_global_config())
    }

    fn process_global_config(mut self) -> Result<Self, String> {
        if let Some(config) = self.global.take() {
            let node_count = toml_value_to_string(
                config
                    .get("beacon-count")
                    .ok_or("beacon-count required")?
                    .clone(),
            )?
            .parse::<usize>()
            .map_err(|e| format!("{}", e))?;
            for (k, v) in config {
                match k.as_str() {
                    "validator-count" => {
                        if let Some(config) = self.lcli.new_testnet.as_mut() {
                            config.insert(VALIDATOR_COUNT_FLAG.to_string(), v.clone());
                            config.insert(
                                MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG.to_string(),
                                v.clone(),
                            );
                        }
                        if let Some(config) = self.lcli.deploy_deposit_contract.as_mut() {
                            config.insert(VALIDATOR_COUNT_FLAG.to_string(), v);
                        }
                        let len = self.validator.len();
                        if let Some(config) = self.validator.get_mut("default") {
                            let mut i = 0;
                            let config_clone = config.clone();
                            while i < node_count - len {
                                i = i + 1;
                                self.validator
                                    .insert(format!("default-{}", i), config_clone.clone());
                            }
                        } else {
                            if self.validator.len() != node_count {
                                return Err("defaults need to be defined if all nodes are not explicitly defined".to_string());
                            }
                        }
                    }
                    "beacon-count" => {
                        let len = self.beacon.len();
                        if let Some(config) = self.beacon.get_mut("default") {
                            let mut i = 0;
                            let config_clone = config.clone();
                            while i < node_count - len {
                                i = i + 1;
                                self.beacon
                                    .insert(format!("default-{}", i), config_clone.clone());
                            }
                        } else {
                            if self.beacon.len() != node_count {
                                return Err("defaults need to be defined if all nodes are not explicitly defined".to_string());
                            }
                        }
                    }
                    "spec" => {
                        if let Some(config) = self.lcli.new_testnet.as_mut() {
                            config.insert(SPEC_FLAG.to_string(), v.clone());
                        }
                    }
                    "datadir" => {
                        let (testnet_dir, bootnode_dir) = match v {
                            TomlValue::String(ref s) => (
                                TomlValue::String(format!("{}/testnet", s)),
                                TomlValue::String(format!("{}/bootnode", s)),
                            ),
                            _ => return Err("invalid datadir".to_string()),
                        };
                        if let Some(config) = self.lcli.new_testnet.as_mut() {
                            config.insert(TESTNET_DIR_FLAG.to_string(), testnet_dir.clone());
                            config.insert(BOOT_DIR_FLAG.to_string(), bootnode_dir.clone());
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
                        // can't insert data dir into all beacon and validator nodes here, because they need to increment, so config has to be duplicated first
                        self.datadir = Some(toml_value_to_string(v)?);
                    }
                    other => return Err(format!("invalid global config: {}", other)),
                }
            }
        }
        Ok(self)
    }

    pub fn start_testnet(&mut self) -> Result<Testnet, String> {
        // cleanup previous testnet files
        if let Some(dir) = self.datadir.as_ref() {
            let path = PathBuf::from(dir);
            if path.exists() {
                fs::remove_dir_all(dir).map_err(|e| format!("failed to remove datadir: {}", e))?;
            }
        }

        let ganache = self.start_ganache()?;
        self.setup_lcli()?;
        let bootnode = self.spawn_bootnode()?;
        let beacon_nodes = self.spawn_beacon_nodes()?;
        let validator_clients = self.spawn_validator_clients()?;

        Ok(Testnet {
            ganache,
            bootnode,
            beacon_nodes,
            validator_clients,
            datadir: self.datadir.clone().unwrap(),
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

    fn setup_lcli(&mut self) -> Result<(), String> {
        let config = to_string_map(
            self.lcli
                .deploy_deposit_contract
                .take()
                .ok_or("unable to parse deploy contract config")?,
            toml_value_to_string,
        )?;

        let mut deploy_config: Vec<_> = config
            .into_iter()
            .flat_map(|(k, v)| {
                if v == "true" {
                    vec![format!("--{}", k)].into_iter()
                } else {
                    vec![format!("--{}", k), v].into_iter()
                }
            })
            .collect();
        deploy_config.insert(0, DEPLOY_DEPOSIT_CONTRACT_CMD.to_string());
        deploy_config.insert(0, LCLI_CMD.to_string());

        let app = lcli::new_app(None)
            .try_get_matches_from(deploy_config)
            .map_err(|e| format!("{}", e))?;
        lcli::run(&app)?;

        let config = to_string_map(
            self.lcli
                .new_testnet
                .take()
                .ok_or("unable to parse new testnet config")?,
            toml_value_to_string,
        )?;

        // Setup genesis time
        let mut testnet_config: Vec<_> = config
            .into_iter()
            .flat_map(|(k, v)| {
                if v == "true" {
                    vec![format!("--{}", k)].into_iter()
                } else if k == GENESIS_DELAY_FLAG {
                    let genesis_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("invalid genesis delay")
                        .as_secs()
                        .to_string();
                    vec![
                        format!("--{}", k),
                        v,
                        format!("--{}", GENESIS_TIME_FLAG),
                        genesis_time,
                    ]
                    .into_iter()
                } else {
                    vec![format!("--{}", k), v].into_iter()
                }
            })
            .collect();
        testnet_config.insert(0, NEW_TESTNET_CMD.to_string());
        testnet_config.insert(0, LCLI_CMD.to_string());

        let app = lcli::new_app(None)
            .try_get_matches_from(testnet_config)
            .map_err(|e| format!("{}", e))?;
        lcli::run(&app)?;

        let app = lcli::new_app(None)
            .try_get_matches_from(vec![
                "lcli",
                "insecure-validators",
                "--base-dir",
                self.datadir.as_ref().unwrap(),
                "--count",
                &format!("{}", self.validator.len()),
                "--node-count",
                &format!("{}", self.beacon.len()),
            ])
            .map_err(|e| format!("{}", e))?;
        lcli::run(&app)?;

        Ok(())
    }

    fn spawn_bootnode(&mut self) -> Result<SimProcess, String> {
        let config = to_string_map(
            self.boot_node
                .take()
                .ok_or("unable to parse boot node config")?,
            toml_value_to_string,
        )?;

        let mut process = SimProcess::new_lighthouse_process(BOOT_NODE_CMD, config).spawn_no_wait();

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
                    format!("{}/node_{}", self.datadir.as_ref().unwrap(), index),
                );
                config.insert(PORT_FLAG.to_string(), format!("9{}00", index));
                config.insert(HTTP_PORT_FLAG.to_string(), format!("5{}52", index));
            } else {
                config.entry(DATADIR_FLAG.to_string()).or_insert(format!(
                    "{}/node_{}",
                    self.datadir.as_ref().unwrap(),
                    index
                ));
                config
                    .entry(PORT_FLAG.to_string())
                    .or_insert(format!("9{}00", index));
                config
                    .entry(HTTP_PORT_FLAG.to_string())
                    .or_insert(format!("5{}52", index));
            }
            let process = SimProcess::new_lighthouse_process(BEACON_CMD, config).spawn_no_wait();
            processes.push(process);
        }

        Ok(processes)
    }

    fn spawn_validator_clients(&mut self) -> Result<Vec<SimProcess>, String> {
        let mut processes = vec![];

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
                    format!("{}/node_{}", self.datadir.as_ref().unwrap(), index),
                );
                config.insert(
                    BEACON_NODES_FLAG.to_string(),
                    format!("http://localhost:5{}52", index),
                );
            } else {
                config.entry(DATADIR_FLAG.to_string()).or_insert(format!(
                    "{}/node_{}",
                    self.datadir.as_ref().unwrap(),
                    index
                ));
                config
                    .entry(BEACON_NODES_FLAG.to_string())
                    .or_insert(format!("localhost:5{}52", index));
            }
            let process = SimProcess::new_lighthouse_process(VALIDATOR_CMD, config).spawn_no_wait();
            processes.push(process);
        }

        Ok(processes)
    }
}

pub struct Testnet {
    ganache: SimProcess,
    bootnode: SimProcess,
    beacon_nodes: Vec<SimProcess>,
    validator_clients: Vec<SimProcess>,
    datadir: String,
}

impl Testnet {}

fn parse_file_config_maps(file_name: &str) -> Result<IntegrationTestConfig, String> {
    if file_name.ends_with(".toml") {
        fs::read_to_string(file_name)
            .map_err(|e| e.to_string())
            .and_then(|toml| toml::from_str(toml.as_str()).map_err(|e| e.to_string()))
    } else {
        Err("config file must have extension `.toml`".to_string())
    }
}

#[derive(Debug)]
pub struct SimProcess {
    cmd: Option<Command>,
    process: Option<Child>,
}

impl Drop for SimProcess {
    fn drop(&mut self) {
        if let Some(child) = self.process.as_mut() {
            child.kill();
        };
    }
}

impl SimProcess {
    pub fn new(base_cmd_name: &str, config: HashMap<String, String>) -> SimProcess {
        let mut cmd = Command::new(base_cmd_name);
        for (k, v) in config.into_iter() {
            cmd.arg(format!("--{}", k));
            cmd.arg(v);
        }
        SimProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn new_lighthouse_process(
        base_cmd_name: &str,
        config: HashMap<String, String>,
    ) -> SimProcess {
        let lighthouse_bin = env!("CARGO_BIN_EXE_lighthouse");
        let path = lighthouse_bin
            .parse::<PathBuf>()
            .expect("should parse CARGO_TARGET_DIR");

        let mut cmd = Command::new(path);
        cmd.arg(base_cmd_name);
        for (k, v) in config.into_iter() {
            if v == "true" {
                cmd.arg(format!("--{}", k));
            } else {
                cmd.arg(format!("--{}", k));
                cmd.arg(v);
            }
        }
        SimProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn spawn_no_wait(mut self) -> Self {
        self.process = Some(
            self.cmd
                .take()
                .expect("command cannot be called twice")
                .spawn()
                .expect("should start process"),
        );
        self
    }

    pub fn spawn_and_wait(&mut self) -> ExitStatus {
        self.cmd
            .take()
            .expect("command cannot be called twice")
            .spawn()
            .expect("should start process")
            .wait()
            .expect("spawned process should be running")
    }

    pub fn wait(&mut self) -> ExitStatus {
        self.process
            .as_mut()
            .expect("simulator process should be running")
            .wait()
            .expect("child process should be running")
    }

    pub fn kill_process(&mut self) {
        self.process
            .as_mut()
            .expect("simulator process should be running")
            .kill()
            .expect("child process should be running")
    }
}

// fn spawn_validator(
//     beacon_port: usize,
//     http_port: usize,
//     index: usize,
// ) -> (SimProcess, ValidatorClientHttpClient) {
//     let datadir = format!("{}{}", "~/.lighthouse/local-testnet/node_", index);
//     let url = format!("{}{}", "http://localhost:", beacon_port);
//     let process = SimProcess::new_validator()
//         .flag("debug-level", Some("debug"))
//         .flag("init-slashing-protection", None)
//         .flag("enable-doppelganger-protection", None)
//         .flag("http-port", Some(&format!("{}", http_port)))
//         .flag("beacon-nodes", Some(&url))
//         .flag("datadir", Some(&datadir))
//         .flag(
//             "testnet-dir",
//             Some(&format!("{}", "~/.lighthouse/local-testnet/testnet")),
//         )
//         .spawn_no_wait();
//     thread::sleep(time::Duration::from_secs(20));
//
//     let token_path = PathBuf::from(format!("{}{}", datadir, "/validators/api-token.txt"));
//     dbg!(&token_path);
//     let secret = fs::read_to_string(token_path).expect("should read API token from file");
//     let http_client = ValidatorClientHttpClient::new(
//         SensitiveUrl::parse(&url).expect("should create HTTP client"),
//         secret,
//     )
//     .expect("should create HTTP client");
//     (process, http_client)
// }

#[test]
fn test_1() {
    let mut test = IntegrationTestConfig::new().expect("should parse testnet config");
    let testnet = test.start_testnet().expect("should start testnet");

    thread::sleep(Duration::from_secs(20));
}
