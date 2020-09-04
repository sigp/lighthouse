use clap::ArgMatches;
pub use eth2_testnet_config::DEFAULT_HARDCODED_TESTNET;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};

/// Names for the default directories.
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";
pub const DEFAULT_BEACON_NODE_DIR: &str = "beacon";
pub const DEFAULT_NETWORK_DIR: &str = "network";
pub const DEFAULT_VALIDATOR_DIR: &str = "validators";
pub const DEFAULT_SECRET_DIR: &str = "secrets";
pub const DEFAULT_WALLET_DIR: &str = "wallets";

/// Base directory name for unnamed testnets passed through the --testnet-dir flag
pub const CUSTOM_TESTNET_DIR: &str = "custom";

/// Gets the testnet directory name
///
/// Tries to get the name first from the "testnet" flag,
/// if not present, then checks the "testnet-dir" flag and returns a custom name
/// If neither flags are present, returns the default hardcoded network name.
pub fn get_testnet_name(matches: &ArgMatches) -> String {
    if let Some(testnet_name) = matches.value_of("testnet") {
        testnet_name.to_string()
    } else if matches.value_of("testnet-dir").is_some() {
        CUSTOM_TESTNET_DIR.to_string()
    } else {
        eth2_testnet_config::DEFAULT_HARDCODED_TESTNET.to_string()
    }
}

/// Checks if a directory exists in the given path and creates a directory if it does not exist.
pub fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let path = path.as_ref();

    if !path.exists() {
        create_dir_all(path).map_err(|e| format!("Unable to create {:?}: {:?}", path, e))?;
    }

    Ok(())
}

/// If `arg` is in `matches`, parses the value as a path.
///
/// Otherwise, attempts to find the default directory for the `testnet` from the `matches`
/// and appends `flag` to it.
pub fn parse_path_or_default_with_flag(
    matches: &ArgMatches,
    arg: &'static str,
    flag: &str,
) -> Result<PathBuf, String> {
    clap_utils::parse_path_with_default_in_home_dir(
        matches,
        arg,
        PathBuf::new()
            .join(DEFAULT_ROOT_DIR)
            .join(get_testnet_name(matches))
            .join(flag),
    )
}
