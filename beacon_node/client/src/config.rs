use crate::{Bootstrapper, Eth2Config};
use clap::ArgMatches;
use network::NetworkConfig;
use serde_derive::{Deserialize, Serialize};
use slog::{info, o, warn, Drain};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::sync::Mutex;

/// The number initial validators when starting the `Minimal`.
const TESTNET_VALIDATOR_COUNT: usize = 16;

/// The number initial validators when starting the `Minimal`.
const TESTNET_SPEC_CONSTANTS: &str = "minimal";

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub db_type: String,
    db_name: String,
    pub log_file: PathBuf,
    pub spec_constants: String,
    pub genesis_state: GenesisState,
    pub network: network::NetworkConfig,
    pub rpc: rpc::RPCConfig,
    pub rest_api: rest_api::ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GenesisState {
    /// Use the mainnet genesis state.
    ///
    /// Mainnet genesis state is not presently known, so this is a place-holder.
    Mainnet,
    /// Generate a state with `validator_count` validators, all with well-known secret keys.
    ///
    /// Set the genesis time to be the start of the previous 30-minute window.
    RecentGenesis { validator_count: usize },
    /// Generate a state with `genesis_time` and `validator_count` validators, all with well-known
    /// secret keys.
    Generated {
        validator_count: usize,
        genesis_time: u64,
    },
    /// Load a YAML-encoded genesis state from a file.
    Yaml { file: PathBuf },
    /// Use a HTTP server (running our REST-API) to load genesis and finalized states and blocks.
    HttpBootstrap { server: String },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".lighthouse"),
            log_file: PathBuf::from(""),
            db_type: "disk".to_string(),
            db_name: "chain_db".to_string(),
            network: NetworkConfig::new(),
            rpc: rpc::RPCConfig::default(),
            rest_api: rest_api::ApiConfig::default(),
            spec_constants: TESTNET_SPEC_CONSTANTS.into(),
            genesis_state: GenesisState::RecentGenesis {
                validator_count: TESTNET_VALIDATOR_COUNT,
            },
        }
    }
}

impl Config {
    /// Returns the path to which the client may initialize an on-disk database.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.data_dir()
            .and_then(|path| Some(path.join(&self.db_name)))
    }

    /// Returns the core path for the client.
    pub fn data_dir(&self) -> Option<PathBuf> {
        let path = dirs::home_dir()?.join(&self.data_dir);
        fs::create_dir_all(&path).ok()?;
        Some(path)
    }

    // Update the logger to output in JSON to specified file
    fn update_logger(&mut self, log: &mut slog::Logger) -> Result<(), &'static str> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.log_file);

        if file.is_err() {
            return Err("Cannot open log file");
        }
        let file = file.unwrap();

        if let Some(file) = self.log_file.to_str() {
            info!(
                *log,
                "Log file specified, output will now be written to {} in json.", file
            );
        } else {
            info!(
                *log,
                "Log file specified output will now be written in json"
            );
        }

        let drain = Mutex::new(slog_json::Json::default(file)).fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        *log = slog::Logger::root(drain, o!());

        Ok(())
    }

    /// Apply the following arguments to `self`, replacing values if they are specified in `args`.
    ///
    /// Returns an error if arguments are obviously invalid. May succeed even if some values are
    /// invalid.
    pub fn apply_cli_args(
        &mut self,
        args: &ArgMatches,
        log: &mut slog::Logger,
    ) -> Result<(), String> {
        if let Some(dir) = args.value_of("datadir") {
            self.data_dir = PathBuf::from(dir);
        };

        if let Some(default_spec) = args.value_of("default-spec") {
            match default_spec {
                "mainnet" => self.spec_constants = Eth2Config::mainnet().spec_constants,
                "minimal" => self.spec_constants = Eth2Config::minimal().spec_constants,
                "interop" => self.spec_constants = Eth2Config::interop().spec_constants,
                _ => {} // not supported
            }
        }

        if let Some(dir) = args.value_of("db") {
            self.db_type = dir.to_string();
        };

        self.network.apply_cli_args(args)?;
        self.rpc.apply_cli_args(args)?;
        self.rest_api.apply_cli_args(args)?;

        if let Some(log_file) = args.value_of("logfile") {
            self.log_file = PathBuf::from(log_file);
            self.update_logger(log)?;
        };

        // If the `--bootstrap` flag is provided, overwrite the default configuration.
        if let Some(server) = args.value_of("bootstrap") {
            do_bootstrapping(self, server.to_string(), &log)?;
        }

        Ok(())
    }
}

/// Perform the HTTP bootstrapping procedure, reading an ENR and multiaddr from the HTTP server and
/// adding them to the `config`.
fn do_bootstrapping(config: &mut Config, server: String, log: &slog::Logger) -> Result<(), String> {
    // Set the genesis state source.
    config.genesis_state = GenesisState::HttpBootstrap {
        server: server.to_string(),
    };

    let bootstrapper = Bootstrapper::from_server_string(server.to_string())?;

    config.network.boot_nodes.push(bootstrapper.enr()?);

    if let Some(server_multiaddr) = bootstrapper.best_effort_multiaddr() {
        info!(
            log,
            "Estimated bootstrapper libp2p address";
            "multiaddr" => format!("{:?}", server_multiaddr)
        );
        config.network.libp2p_nodes.push(server_multiaddr);
    } else {
        warn!(
            log,
            "Unable to estimate a bootstrapper libp2p address, this node may not find any peers."
        );
    }

    Ok(())
}
