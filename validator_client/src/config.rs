use clap::ArgMatches;
use slog::{error, info};
use std::fs;
use std::path::PathBuf;
use types::ChainSpec;

/// Stores the core configuration for this validator instance.
#[derive(Clone)]
pub struct ClientConfig {
    pub data_dir: PathBuf,
    pub server: String,
    pub spec: ChainSpec,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse-validators";

impl ClientConfig {
    /// Build a new configuration from defaults.
    pub fn default() -> Self {
        let data_dir = {
            let home = dirs::home_dir().expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        fs::create_dir_all(&data_dir)
            .unwrap_or_else(|_| panic!("Unable to create {:?}", &data_dir));
        let server = "localhost:5051".to_string();
        let spec = ChainSpec::foundation();
        Self {
            data_dir,
            server,
            spec,
        }
    }

    pub fn parse_args(matches: ArgMatches, log: &slog::Logger) -> Result<Self, &'static str> {
        let mut config = ClientConfig::default();
        // Custom datadir
        if let Some(dir) = matches.value_of("datadir") {
            config.data_dir = PathBuf::from(dir.to_string());
        }

        // Custom server port
        if let Some(server_str) = matches.value_of("server") {
            if let Ok(addr) = server_str.parse::<u16>() {
                config.server = addr.to_string();
            } else {
                error!(log, "Invalid address"; "server" => server_str);
                return Err("Invalid address");
            }
        }

        // TODO: Permit loading a custom spec from file.
        // Custom spec
        if let Some(spec_str) = matches.value_of("spec") {
            match spec_str {
                "foundation" => config.spec = ChainSpec::foundation(),
                "few_validators" => config.spec = ChainSpec::few_validators(),
                // Should be impossible due to clap's `possible_values(..)` function.
                _ => unreachable!(),
            };
        }

        // Log configuration
        info!(log, "";
              "data_dir" => &config.data_dir.to_str(),
              "server" => &config.server);
        Ok(config)
    }
}
