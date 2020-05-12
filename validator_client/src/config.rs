use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_HTTP_SERVER: &str = "http://localhost:5052/";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse/validators";
pub const DEFAULT_SECRET_DIR: &str = ".lighthouse/secrets";

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// The directory containing the passwords to unlock validator keystores.
    pub secrets_dir: PathBuf,
    /// If `true`, load the legacy-style unencrypted keys from disk.
    ///
    /// This feature should be removed very soon.
    pub use_legacy_keys: bool,
    /// The http endpoint of the beacon node API.
    ///
    /// Should be similar to `http://localhost:8080`
    pub http_server: String,
    /// If true, the validator client will still poll for duties and produce blocks even if the
    /// beacon node is not synced at startup.
    pub allow_unsynced_beacon_node: bool,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lighthouse");
        let data_dir = base_dir.join("validators");
        let secrets_dir = base_dir.join("secrets");

        Self {
            data_dir,
            secrets_dir,
            use_legacy_keys: false,
            http_server: DEFAULT_HTTP_SERVER.to_string(),
            allow_unsynced_beacon_node: false,
        }
    }
}

impl Config {
    /// Returns a `Default` implementation of `Self` with some parameters modified by the supplied
    /// `cli_args`.
    pub fn from_cli(cli_args: &ArgMatches) -> Result<Config, String> {
        let mut config = Config::default();

        // Read the `--datadir` flag.
        //
        // If it's not present, try and find the home directory (`~`) and push the default data
        // directory onto it. If the home directory is not available, use the present directory.
        config.data_dir = cli_args
            .value_of("datadir")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .map(|home| home.join(DEFAULT_DATA_DIR))
                    .unwrap_or_else(|| PathBuf::from("."))
            });

        if let Some(server) = cli_args.value_of("server") {
            config.http_server = server.to_string();
        }

        config.allow_unsynced_beacon_node = cli_args.is_present("allow-unsynced");

        config.use_legacy_keys = cli_args.is_present("legacy-keys");

        Ok(config)
    }
}
