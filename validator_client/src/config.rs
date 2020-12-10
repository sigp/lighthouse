use crate::{http_api, http_metrics};
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use directory::{
    get_network_dir, DEFAULT_HARDCODED_NETWORK, DEFAULT_ROOT_DIR, DEFAULT_SECRET_DIR,
    DEFAULT_VALIDATOR_DIR,
};
use eth2::types::Graffiti;
use serde_derive::{Deserialize, Serialize};
use slog::{warn, Logger};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use types::GRAFFITI_BYTES_LEN;

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub validator_dir: PathBuf,
    /// The directory containing the passwords to unlock validator keystores.
    pub secrets_dir: PathBuf,
    /// The http endpoint of the beacon node API.
    ///
    /// Should be similar to `http://localhost:8080`
    pub beacon_node: String,
    /// If true, the validator client will still poll for duties and produce blocks even if the
    /// beacon node is not synced at startup.
    pub allow_unsynced_beacon_node: bool,
    /// If true, don't scan the validators dir for new keystores.
    pub disable_auto_discover: bool,
    /// If true, re-register existing validators in definitions.yml for slashing protection.
    pub init_slashing_protection: bool,
    /// Graffiti to be inserted everytime we create a block.
    pub graffiti: Option<Graffiti>,
    /// Configuration for the HTTP REST API.
    pub http_api: http_api::Config,
    /// Configuration for the HTTP REST API.
    pub http_metrics: http_metrics::Config,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        // WARNING: these directory defaults should be always overwritten with parameters from cli
        // for specific networks.
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK);
        let validator_dir = base_dir.join(DEFAULT_VALIDATOR_DIR);
        let secrets_dir = base_dir.join(DEFAULT_SECRET_DIR);
        Self {
            validator_dir,
            secrets_dir,
            beacon_node: DEFAULT_BEACON_NODE.to_string(),
            allow_unsynced_beacon_node: false,
            disable_auto_discover: false,
            init_slashing_protection: false,
            graffiti: None,
            http_api: <_>::default(),
            http_metrics: <_>::default(),
        }
    }
}

impl Config {
    /// Returns a `Default` implementation of `Self` with some parameters modified by the supplied
    /// `cli_args`.
    pub fn from_cli(cli_args: &ArgMatches, log: &Logger) -> Result<Config, String> {
        let mut config = Config::default();

        let default_root_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_ROOT_DIR))
            .unwrap_or_else(|| PathBuf::from("."));

        let (mut validator_dir, mut secrets_dir) = (None, None);
        if cli_args.value_of("datadir").is_some() {
            let base_dir: PathBuf = parse_required(cli_args, "datadir")?;
            validator_dir = Some(base_dir.join(DEFAULT_VALIDATOR_DIR));
            secrets_dir = Some(base_dir.join(DEFAULT_SECRET_DIR));
        }
        if cli_args.value_of("validators-dir").is_some() {
            validator_dir = Some(parse_required(cli_args, "validators-dir")?);
        }
        if cli_args.value_of("secrets-dir").is_some() {
            secrets_dir = Some(parse_required(cli_args, "secrets-dir")?);
        }

        config.validator_dir = validator_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(cli_args))
                .join(DEFAULT_VALIDATOR_DIR)
        });

        config.secrets_dir = secrets_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(cli_args))
                .join(DEFAULT_SECRET_DIR)
        });

        if !config.validator_dir.exists() {
            fs::create_dir_all(&config.validator_dir)
                .map_err(|e| format!("Failed to create {:?}: {:?}", config.validator_dir, e))?;
        }

        if let Some(beacon_node) = parse_optional(cli_args, "beacon-node")? {
            config.beacon_node = beacon_node;
        }

        // To be deprecated.
        if let Some(server) = parse_optional(cli_args, "server")? {
            warn!(
                log,
                "The --server flag is deprecated";
                "msg" => "please use --beacon-node instead"
            );
            config.beacon_node = server;
        }

        if cli_args.is_present("delete-lockfiles") {
            warn!(
                log,
                "The --delete-lockfiles flag is deprecated";
                "msg" => "it is no longer necessary, and no longer has any effect",
            );
        }

        config.allow_unsynced_beacon_node = cli_args.is_present("allow-unsynced");
        config.disable_auto_discover = cli_args.is_present("disable-auto-discover");
        config.init_slashing_protection = cli_args.is_present("init-slashing-protection");

        if let Some(input_graffiti) = cli_args.value_of("graffiti") {
            let graffiti_bytes = input_graffiti.as_bytes();
            if graffiti_bytes.len() > GRAFFITI_BYTES_LEN {
                return Err(format!(
                    "Your graffiti is too long! {} bytes maximum!",
                    GRAFFITI_BYTES_LEN
                ));
            } else {
                let mut graffiti = [0; 32];

                // Copy the provided bytes over.
                //
                // Panic-free because `graffiti_bytes.len()` <= `GRAFFITI_BYTES_LEN`.
                graffiti[..graffiti_bytes.len()].copy_from_slice(&graffiti_bytes);

                config.graffiti = Some(graffiti.into());
            }
        }

        /*
         * Http API server
         */

        if cli_args.is_present("http") {
            config.http_api.enabled = true;
        }

        if let Some(port) = cli_args.value_of("http-port") {
            config.http_api.listen_port = port
                .parse::<u16>()
                .map_err(|_| "http-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.value_of("http-allow-origin") {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        /*
         * Prometheus metrics HTTP server
         */

        if cli_args.is_present("metrics") {
            config.http_metrics.enabled = true;
        }

        if let Some(address) = cli_args.value_of("metrics-address") {
            config.http_metrics.listen_addr = address
                .parse::<Ipv4Addr>()
                .map_err(|_| "metrics-address is not a valid IPv4 address.")?;
        }

        if let Some(port) = cli_args.value_of("metrics-port") {
            config.http_metrics.listen_port = port
                .parse::<u16>()
                .map_err(|_| "metrics-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.value_of("metrics-allow-origin") {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_metrics.allow_origin = Some(allow_origin.to_string());
        }

        Ok(config)
    }
}
