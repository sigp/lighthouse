use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::ops::Range;
use std::path::PathBuf;
use types::{EthSpec, MainnetEthSpec};

#[derive(Clone)]
pub enum KeySource {
    /// Load the keypairs from disk.
    Disk,
    /// Generate the keypairs (insecure, generates predictable keys).
    TestingKeypairRange(Range<usize>),
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
    /// The source for loading keypairs
    #[serde(skip)]
    pub key_source: KeySource,
    /// The path where the logs will be outputted
    pub log_file: PathBuf,
    /// The server at which the Beacon Node can be contacted
    pub server: String,
    /// The gRPC port on the server
    pub server_grpc_port: u16,
    /// The HTTP port on the server, for the REST API.
    pub server_http_port: u16,
    /// The number of slots per epoch.
    pub slots_per_epoch: u64,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".lighthouse/validators"),
            key_source: <_>::default(),
            log_file: PathBuf::from(""),
            server: "localhost".into(),
            server_grpc_port: 5051,
            server_http_port: 5052,
            slots_per_epoch: MainnetEthSpec::slots_per_epoch(),
        }
    }
}

impl Config {
    /// Parses the CLI arguments and attempts to load the client configuration.
    pub fn from_cli(cli_args: &ArgMatches) -> Result<Config, String> {
        let mut client_config = Config::default();

        if let Some(datadir) = cli_args.value_of("datadir") {
            client_config.data_dir = PathBuf::from(datadir);
        };

        if let Some(server) = cli_args.value_of("server") {
            client_config.server = server.to_string();
        }

        if let Some(port) = cli_args.value_of("server-http-port") {
            client_config.server_http_port = port
                .parse::<u16>()
                .map_err(|e| format!("Unable to parse HTTP port: {:?}", e))?;
        }

        if let Some(port) = cli_args.value_of("server-grpc-port") {
            client_config.server_grpc_port = port
                .parse::<u16>()
                .map_err(|e| format!("Unable to parse gRPC port: {:?}", e))?;
        }

        let client_config = match cli_args.subcommand() {
            ("testnet", Some(sub_cli_args)) => {
                if cli_args.is_present("eth2-config") && sub_cli_args.is_present("bootstrap") {
                    return Err(
                        "Cannot specify --eth2-config and --bootstrap as it may result \
                         in ambiguity."
                            .into(),
                    );
                }
                process_testnet_subcommand(sub_cli_args, client_config)
            }
            _ => return Err("You must use the testnet command. See '--help'.".into()),
        }?;

        Ok(client_config)
    }
}

/// Parses the `testnet` CLI subcommand.
fn process_testnet_subcommand(
    cli_args: &ArgMatches,
    mut client_config: Config,
) -> Result<Config, String> {
    client_config.key_source = match cli_args.subcommand() {
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

            KeySource::TestingKeypairRange(first..last)
        }
        _ => KeySource::Disk,
    };

    Ok(client_config)
}
