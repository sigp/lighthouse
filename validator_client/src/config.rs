use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_HTTP_SERVER: &str = "http://localhost:5052/";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse/validators";

/// Specifies a method for obtaining validator keypairs.
#[derive(Clone)]
pub enum KeySource {
    /// Load the keypairs from disk.
    Disk,
    /// Generate the keypairs (insecure, generates predictable keys).
    InsecureKeypairs(Vec<usize>),
}

impl Default for KeySource {
    fn default() -> Self {
        KeySource::Disk
    }
}

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub data_dir: PathBuf,
    /// Specifies how the validator client should load keypairs.
    #[serde(skip)]
    pub key_source: KeySource,
    /// The http endpoint of the beacon node API.
    ///
    /// Should be similar to `http://localhost:8080`
    pub http_server: String,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        let mut data_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        data_dir.push(".lighthouse");
        data_dir.push("validators");
        Self {
            data_dir,
            key_source: <_>::default(),
            http_server: DEFAULT_HTTP_SERVER.to_string(),
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

        let config = match cli_args.subcommand() {
            ("testnet", Some(sub_cli_args)) => {
                if cli_args.is_present("eth2-config") && sub_cli_args.is_present("bootstrap") {
                    return Err(
                        "Cannot specify --eth2-config and --bootstrap as it may result \
                         in ambiguity."
                            .into(),
                    );
                }
                process_testnet_subcommand(sub_cli_args, config)?
            }
            _ => {
                config.key_source = KeySource::Disk;
                config
            }
        };

        Ok(config)
    }
}

/// Parses the `testnet` CLI subcommand, modifying the `config` based upon the parameters in
/// `cli_args`.
fn process_testnet_subcommand(cli_args: &ArgMatches, mut config: Config) -> Result<Config, String> {
    config.key_source = match cli_args.subcommand() {
        ("insecure", Some(sub_cli_args)) => {
            let first = sub_cli_args
                .value_of("first_validator")
                .ok_or_else(|| "No first validator supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first validator: {:?}", e))?;
            let last = sub_cli_args
                .value_of("last_validator")
                .ok_or_else(|| "No last validator supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse last validator: {:?}", e))?;

            if last < first {
                return Err("Cannot supply a last validator less than the first".to_string());
            }

            KeySource::InsecureKeypairs((first..last).collect())
        }
        _ => KeySource::Disk,
    };

    Ok(config)
}
