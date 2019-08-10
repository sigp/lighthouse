use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::SystemTime;
use types::ChainSpec;

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Eth2Config {
    pub spec_constants: String,
    pub spec: ChainSpec,
}

impl Default for Eth2Config {
    fn default() -> Self {
        Self {
            spec_constants: "minimal".to_string(),
            spec: ChainSpec::minimal(),
        }
    }
}

impl Eth2Config {
    pub fn mainnet() -> Self {
        Self {
            spec_constants: "mainnet".to_string(),
            spec: ChainSpec::mainnet(),
        }
    }

    pub fn minimal() -> Self {
        Self {
            spec_constants: "minimal".to_string(),
            spec: ChainSpec::minimal(),
        }
    }

    pub fn interop() -> Self {
        Self {
            spec_constants: "interop".to_string(),
            spec: ChainSpec::interop(),
        }
    }
}

impl Eth2Config {
    /// Apply the following arguments to `self`, replacing values if they are specified in `args`.
    ///
    /// Returns an error if arguments are obviously invalid. May succeed even if some values are
    /// invalid.
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if args.is_present("recent-genesis") {
            self.spec.min_genesis_time = recent_genesis_time()
        }

        Ok(())
    }
}

/// Returns the system time, mod 30 minutes.
///
/// Used for easily creating testnets.
fn recent_genesis_time() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(30 * 60).unwrap_or(0);
    // genesis is now the last 30 minute block.
    now - secs_after_last_period
}

/// Write a configuration to file.
pub fn write_to_file<T>(path: PathBuf, config: &T) -> Result<(), String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(mut file) = File::create(path.clone()) {
        let toml_encoded = toml::to_string(&config).map_err(|e| {
            format!(
                "Failed to write configuration to {:?}. Error: {:?}",
                path, e
            )
        })?;
        file.write_all(toml_encoded.as_bytes())
            .unwrap_or_else(|_| panic!("Unable to write to {:?}", path));
    }

    Ok(())
}

/// Loads a `ClientConfig` from file. If unable to load from file, generates a default
/// configuration and saves that as a sample file.
pub fn read_from_file<T>(path: PathBuf) -> Result<Option<T>, String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(mut file) = File::open(path.clone()) {
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Unable to read {:?}. Error: {:?}", path, e))?;

        let config = toml::from_str(&contents)
            .map_err(|e| format!("Unable to parse {:?}: {:?}", path, e))?;

        Ok(Some(config))
    } else {
        Ok(None)
    }
}
