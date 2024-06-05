use clap::ArgMatches;
pub use eth2_network_config::DEFAULT_HARDCODED_NETWORK;
use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};

/// Names for the default directories.
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";
pub const DEFAULT_BEACON_NODE_DIR: &str = "beacon";
pub const DEFAULT_NETWORK_DIR: &str = "network";
pub const DEFAULT_VALIDATOR_DIR: &str = "validators";
pub const DEFAULT_SECRET_DIR: &str = "secrets";
pub const DEFAULT_WALLET_DIR: &str = "wallets";
pub const DEFAULT_TRACING_DIR: &str = "tracing";

/// Base directory name for unnamed testnets passed through the --testnet-dir flag
pub const CUSTOM_TESTNET_DIR: &str = "custom";

/// Gets the network directory name
///
/// Tries to get the name first from the "network" flag,
/// if not present, then checks the "testnet-dir" flag and returns a custom name
/// If neither flags are present, returns the default hardcoded network name.
pub fn get_network_dir(matches: &ArgMatches) -> String {
    if let Some(network_name) = matches.get_one::<String>("network") {
        network_name.to_string()
    } else if matches.get_one::<String>("testnet-dir").is_some() {
        CUSTOM_TESTNET_DIR.to_string()
    } else {
        eth2_network_config::DEFAULT_HARDCODED_NETWORK.to_string()
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
/// Otherwise, attempts to find the default directory for the `testnet` from the `matches`.
pub fn parse_path_or_default(matches: &ArgMatches, arg: &'static str) -> Result<PathBuf, String> {
    clap_utils::parse_path_with_default_in_home_dir(
        matches,
        arg,
        PathBuf::new()
            .join(DEFAULT_ROOT_DIR)
            .join(get_network_dir(matches)),
    )
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
            .join(get_network_dir(matches))
            .join(flag),
    )
}

/// Get the approximate size of a directory and its contents.
///
/// Will skip unreadable files, and files. Not 100% accurate if files are being created and deleted
/// while this function is running.
pub fn size_of_dir(path: &Path) -> u64 {
    if let Ok(iter) = fs::read_dir(path) {
        iter.filter_map(std::result::Result::ok)
            .map(size_of_dir_entry)
            .sum()
    } else {
        0
    }
}

fn size_of_dir_entry(dir: fs::DirEntry) -> u64 {
    dir.metadata().map(|m| m.len()).unwrap_or(0)
}
