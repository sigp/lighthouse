use clap::ArgMatches;
pub use eth2_network_config::DEFAULT_HARDCODED_NETWORK;
use std::collections::VecDeque;
use std::fs;
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
/// - Skips unreadable entries and symlinks.
/// - Bounds traversal by depth and total entries to limit potential DoS from deeply nested trees.
/// - Not 100% accurate if files are being created and deleted while this function is running.
pub fn size_of_dir(path: &Path) -> u64 {
    const MAX_DEPTH: usize = 64;
    const MAX_TOTAL_ENTRIES: usize = 100_000;

    let mut total_size = 0u64;
    let mut entries_seen = 0usize;

    let mut stack = VecDeque::new();
    stack.push_back((path.to_path_buf(), 0usize));

    while let Some((dir_path, depth)) = stack.pop_back() {
        if depth > MAX_DEPTH {
            continue;
        }

        let Ok(iter) = fs::read_dir(&dir_path) else {
            continue;
        };

        for entry_result in iter {
            if entries_seen >= MAX_TOTAL_ENTRIES {
                return total_size;
            }

            let Ok(entry) = entry_result else {
                continue;
            };
            entries_seen += 1;

            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            // Use file_type() (non-following) so symlinks are skipped before any metadata lookup.
            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push_back((entry.path(), depth + 1));
                }
            } else {
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                total_size = total_size.saturating_add(metadata.len());
            }
        }
    }

     total_size
}
