use clap::ArgMatches;
use clap_utils::{parse_optional, parse_path_with_default_in_home_dir};
use serde_derive::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;

pub const DEFAULT_HTTP_SERVER: &str = "http://localhost:5052/";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse/validators";
pub const DEFAULT_SECRETS_DIR: &str = ".lighthouse/secrets";
pub const DEFAULT_WALLETS_DIR: &str = ".lighthouse/wallets";
/// Path to the slashing protection database within the datadir.
pub const SLASHING_PROTECTION_FILENAME: &str = "slashing_protection.sqlite";

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The directory containing the passwords to unlock validator keystores.
    pub secrets_dir: PathBuf,
    /// The directory containing wallets (used for key generation).
    pub wallets_dir: PathBuf,
    /// The http endpoint of the beacon node API.
    ///
    /// Should be similar to `http://localhost:8080`
    pub http_server: String,
    /// If true, the validator client will still poll for duties and produce blocks even if the
    /// beacon node is not synced at startup.
    pub allow_unsynced_beacon_node: bool,
    /// If true, refuse to unlock a keypair that is guarded by a lockfile.
    pub strict_lockfiles: bool,
    /// If true, don't scan the validators dir for new keystores.
    pub disable_auto_discover: bool,
    /// Enable the REST API server.
    pub api_enabled: bool,
    /// The IPv4 address the REST API HTTP server will listen on.
    pub api_listen_address: Ipv4Addr,
    /// The port the REST API HTTP server will listen on.
    pub api_port: u16,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        let data_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_DATA_DIR))
            .unwrap_or_else(|| PathBuf::from("."));
        let secrets_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_SECRETS_DIR))
            .unwrap_or_else(|| PathBuf::from("."));
        let wallets_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_WALLETS_DIR))
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir,
            secrets_dir,
            wallets_dir,
            http_server: DEFAULT_HTTP_SERVER.to_string(),
            allow_unsynced_beacon_node: false,
            strict_lockfiles: false,
            disable_auto_discover: false,
            api_enabled: false,
            api_listen_address: Ipv4Addr::new(127, 0, 0, 1),
            api_port: 5054,
        }
    }
}

impl Config {
    /// Returns a `Default` implementation of `Self` with some parameters modified by the supplied
    /// `cli_args`.
    pub fn from_cli(cli_args: &ArgMatches) -> Result<Config, String> {
        let mut config = Config::default();

        config.data_dir = parse_path_with_default_in_home_dir(
            cli_args,
            "datadir",
            PathBuf::from(".lighthouse").join("validators"),
        )?;

        if !config.data_dir.exists() {
            return Err(format!(
                "The directory for validator data  (--datadir) does not exist: {:?}",
                config.data_dir
            ));
        }

        if let Some(server) = parse_optional(cli_args, "server")? {
            config.http_server = server;
        }

        config.allow_unsynced_beacon_node = cli_args.is_present("allow-unsynced");
        config.strict_lockfiles = cli_args.is_present("strict-lockfiles");
        config.disable_auto_discover = cli_args.is_present("disable-auto-discover");

        if let Some(secrets_dir) = parse_optional(cli_args, "secrets-dir")? {
            config.secrets_dir = secrets_dir;
        }

        if let Some(wallets_dir) = parse_optional(cli_args, "wallets-dir")? {
            config.wallets_dir = wallets_dir;
        }

        if !config.secrets_dir.exists() {
            return Err(format!(
                "The directory for validator passwords (--secrets-dir) does not exist: {:?}",
                config.secrets_dir
            ));
        }

        if cli_args.is_present("http") {
            config.api_enabled = true;
        }

        if let Some(address) = cli_args.value_of("http-address") {
            config.api_listen_address = address
                .parse::<Ipv4Addr>()
                .map_err(|_| "http-address is not a valid IPv4 address.")?;
        }
        if let Some(port) = cli_args.value_of("http-port") {
            config.api_port = port
                .parse::<u16>()
                .map_err(|_| "http-port is not a valid u16.")?;
        }

        Ok(config)
    }
}
