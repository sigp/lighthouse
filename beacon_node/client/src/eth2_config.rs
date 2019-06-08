use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
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
}

impl Eth2Config {
    /// Apply the following arguments to `self`, replacing values if they are specified in `args`.
    ///
    /// Returns an error if arguments are obviously invalid. May succeed even if some values are
    /// invalid.
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if args.is_present("recent_genesis") {
            self.spec.genesis_time = recent_genesis_time()
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
