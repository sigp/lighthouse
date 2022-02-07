//! A helper library for parsing values from `clap::ArgMatches`.

use clap::ArgMatches;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use ethereum_types::U256 as Uint256;
use ssz::Decode;
use std::path::PathBuf;
use std::str::FromStr;
use types::{Epoch, Hash256};

pub mod flags;

pub struct GlobalConfig {
    pub config_file: Option<PathBuf>,
    pub spec: Option<String>,
    pub logfile: Option<PathBuf>,
    pub logfile_debug_level: String,
    pub logfile_max_size: u64,
    pub logfile_max_number: usize,
    pub logfile_compress: bool,
    pub log_format: Option<String>,
    pub debug_level: String,
    pub datadir: Option<PathBuf>,
    pub testnet_dir: Option<PathBuf>,
    pub network: Option<String>,
    pub dump_config: Option<PathBuf>,
    pub immediate_shutdown: bool,
    pub disable_malloc_tuning: bool,
    pub terminal_total_difficulty_override: Option<Uint256>,
    pub terminal_block_hash_override: Option<Hash256>,
    pub terminal_block_hash_epoch_override: Option<Epoch>,
}

/// If `name` is in `matches`, parses the value as a path. Otherwise, attempts to find the user's
/// home directory and appends `default` to it.
pub fn parse_path_with_default_in_home_dir(
    config_path: Option<PathBuf>,
    default: PathBuf,
) -> Result<PathBuf, String> {
    if let Some(config_path) = config_path {
        Ok(config_path)
    }else {
            dirs::home_dir()
                .map(|home| home.join(default))
                //TODO: not sure how to make this error specific
                .ok_or_else(|| "Unable to locate home directory".to_string())
        }
}

/// Returns the value of `name` or an error if it is not in `matches` or does not parse
/// successfully using `std::string::FromStr`.
pub fn parse_required<T>(matches: &ArgMatches, name: &str) -> Result<T, String>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    parse_optional(matches, name)?.ok_or_else(|| format!("{} not specified", name))
}

/// Returns the value of `name` (if present) or an error if it does not parse successfully using
/// `std::string::FromStr`.
pub fn parse_optional<T>(matches: &ArgMatches, name: &str) -> Result<Option<T>, String>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    matches
        .value_of(name)
        .map(|val| {
            val.parse()
                .map_err(|e| format!("Unable to parse {}: {}", name, e))
        })
        .transpose()
}

/// Returns the value of `name` or an error if it is not in `matches` or does not parse
/// successfully using `ssz::Decode`.
///
/// Expects the value of `name` to be 0x-prefixed ASCII-hex.
pub fn parse_ssz_required<T: Decode>(
    matches: &ArgMatches,
    name: &'static str,
) -> Result<T, String> {
    parse_ssz_optional(matches, name)?.ok_or_else(|| format!("{} not specified", name))
}

/// Returns the value of `name` (if present) or an error if it does not parse successfully using
/// `ssz::Decode`.
///
/// Expects the value of `name` (if any) to be 0x-prefixed ASCII-hex.
pub fn parse_ssz_optional<T: Decode>(
    matches: &ArgMatches,
    name: &'static str,
) -> Result<Option<T>, String> {
    matches
        .value_of(name)
        .map(|val| {
            if let Some(stripped) = val.strip_prefix("0x") {
                let vec = hex::decode(stripped)
                    .map_err(|e| format!("Unable to parse {} as hex: {:?}", name, e))?;

                T::from_ssz_bytes(&vec)
                    .map_err(|e| format!("Unable to parse {} as SSZ: {:?}", name, e))
            } else {
                Err(format!("Unable to parse {}, must have 0x prefix", name))
            }
        })
        .transpose()
}
