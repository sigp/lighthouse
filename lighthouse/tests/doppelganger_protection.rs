use clap_utils::{to_string_map, toml_value_to_string, TomlValue};
use lcli::new_app;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, io, thread, time};

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
}

pub struct Testnet {
    ganache: SimProcess,
    bootnode: SimProcess,
    beacon_nodes: Vec<SimProcess>,
    validator_clients: Vec<SimProcess>,
}

impl IntegrationTestConfig {
    pub fn new() -> Result<Self, String> {
        parse_file_config_maps("./tests/doppelganger_config/default.toml")
    }

    pub fn start_testnet(&mut self) -> Result<Testnet, String> {
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
        })
    }

    fn start_ganache(&mut self) -> Result<SimProcess, String> {
        let config = to_string_map(
            self.ganache
                .take()
                .ok_or("unable to parse ganache config")?,
            toml_value_to_string,
        )?;

        let mut process = SimProcess::new("ganache-cli", config).spawn_no_wait();

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
        deploy_config.insert(0, "deploy-deposit-contract".to_string());
        deploy_config.insert(0, "lcli".to_string());

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
                } else if k == "genesis-delay" {
                    let genesis_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("invalid genesis delay")
                        .as_secs()
                        .to_string();
                    vec![
                        format!("--{}", k),
                        v,
                        format!("--genesis-time"),
                        genesis_time,
                    ]
                    .into_iter()
                } else {
                    vec![format!("--{}", k), v].into_iter()
                }
            })
            .collect();
        testnet_config.insert(0, "new-testnet".to_string());
        testnet_config.insert(0, "lcli".to_string());

        let app = lcli::new_app(None)
            .try_get_matches_from(testnet_config)
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

        let mut process = SimProcess::new_lighthouse_process("boot_node", config).spawn_no_wait();

        // Need to give boot node time to start up
        thread::sleep(time::Duration::from_secs(5));

        Ok(process)
    }

    fn spawn_beacon_nodes(&mut self) -> Result<Vec<SimProcess>, String> {
        let mut processes = vec![];

        for (name, config) in self.beacon.iter_mut() {
            let config = to_string_map(
                config
                    .take()
                    .ok_or(format!("unable to parse {} config", name))?,
                toml_value_to_string,
            )?;
            let process = SimProcess::new_lighthouse_process("bn", config).spawn_no_wait();
            processes.push(process);
        }

        Ok(processes)
    }

    fn spawn_validator_clients(&mut self) -> Result<Vec<SimProcess>, String> {
        let mut processes = vec![];

        for (name, config) in self.validator.iter_mut() {
            let config = to_string_map(
                config
                    .take()
                    .ok_or(format!("unable to parse {} config", name))?,
                toml_value_to_string,
            )?;
            let process = SimProcess::new_lighthouse_process("vc", config).spawn_no_wait();
            processes.push(process);
        }

        Ok(processes)
    }
}

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
            cmd.arg(format!("--{}", k));
            cmd.arg(v);
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
    let mut test = IntegrationTestConfig::new().unwrap();

    match test.start_testnet() {
        Ok(testnet) => {
            dbg!("successfull setup")
        }
        Err(e) => {
            dbg!(e.as_str())
        }
    };
}
