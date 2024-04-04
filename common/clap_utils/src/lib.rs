//! A helper library for parsing values from `clap::ArgMatches`.

use clap::builder::styling::*;
use clap::ArgMatches;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use ethereum_types::U256 as Uint256;
use ssz::Decode;
use std::path::PathBuf;
use std::str::FromStr;
use types::{ChainSpec, Config, EthSpec};

pub mod flags;

pub const BAD_TESTNET_DIR_MESSAGE: &str = "The hard-coded testnet directory was invalid. \
                                        This happens when Lighthouse is migrating between spec versions \
                                        or when there is no default public network to connect to. \
                                        During these times you must specify a --testnet-dir.";

pub const FLAG_HEADER: &str = "Flags";

/// Try to parse the eth2 network config from the `network`, `testnet-dir` flags in that order.
/// Returns the default hardcoded testnet if neither flags are set.
pub fn get_eth2_network_config(cli_args: &ArgMatches) -> Result<Eth2NetworkConfig, String> {
    let optional_network_config = if cli_args.contains_id("network") {
        parse_hardcoded_network(cli_args, "network")?
    } else if cli_args.contains_id("testnet-dir") {
        parse_testnet_dir(cli_args, "testnet-dir")?
    } else {
        // if neither is present, assume the default network
        Eth2NetworkConfig::constant(DEFAULT_HARDCODED_NETWORK)?
    };

    let mut eth2_network_config =
        optional_network_config.ok_or_else(|| BAD_TESTNET_DIR_MESSAGE.to_string())?;

    if let Some(string) = parse_optional::<String>(cli_args, "terminal-total-difficulty-override")?
    {
        let stripped = string.replace(',', "");
        let terminal_total_difficulty = Uint256::from_dec_str(&stripped).map_err(|e| {
            format!(
                "Could not parse --terminal-total-difficulty-override as decimal value: {:?}",
                e
            )
        })?;

        eth2_network_config.config.terminal_total_difficulty = terminal_total_difficulty;
    }

    if let Some(hash) = parse_optional(cli_args, "terminal-block-hash-override")? {
        eth2_network_config.config.terminal_block_hash = hash;
    }

    if let Some(epoch) = parse_optional(cli_args, "terminal-block-hash-epoch-override")? {
        eth2_network_config
            .config
            .terminal_block_hash_activation_epoch = epoch;
    }

    if let Some(slots) = parse_optional(cli_args, "safe-slots-to-import-optimistically")? {
        eth2_network_config
            .config
            .safe_slots_to_import_optimistically = slots;
    }

    Ok(eth2_network_config)
}

/// Attempts to load the testnet dir at the path if `name` is in `matches`, returning an error if
/// the path cannot be found or the testnet dir is invalid.
pub fn parse_testnet_dir(
    matches: &ArgMatches,
    name: &'static str,
) -> Result<Option<Eth2NetworkConfig>, String> {
    let path = parse_required::<PathBuf>(matches, name)?;
    Eth2NetworkConfig::load(path.clone())
        .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", path, e))
        .map(Some)
}

/// Attempts to load a hardcoded network config if `name` is in `matches`, returning an error if
/// the name is not a valid network name.
pub fn parse_hardcoded_network(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Eth2NetworkConfig>, String> {
    let network_name = parse_required::<String>(matches, name)?;
    Eth2NetworkConfig::constant(network_name.as_str())
}

/// If `name` is in `matches`, parses the value as a path. Otherwise, attempts to find the user's
/// home directory and appends `default` to it.
pub fn parse_path_with_default_in_home_dir(
    matches: &ArgMatches,
    name: &'static str,
    default: PathBuf,
) -> Result<PathBuf, String> {
    matches
        .get_one::<String>(name)
        .map(|dir| {
            dir.parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse {}: {}", name, e))
        })
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|home| home.join(default))
                .ok_or_else(|| format!("Unable to locate home directory. Try specifying {}", name))
        })
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
        .try_get_one::<String>(name)
        .map_err(|e| format!("Unable to parse {}: {}", name, e))?
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
        .get_one::<String>(name)
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

/// Writes configs to file if `dump-config` or `dump-chain-config` flags are set
pub fn check_dump_configs<S, E>(
    matches: &ArgMatches,
    config: S,
    spec: &ChainSpec,
) -> Result<(), String>
where
    S: serde::Serialize,
    E: EthSpec,
{
    if let Some(dump_path) = parse_optional::<PathBuf>(matches, "dump-config")? {
        let mut file = std::fs::File::create(dump_path)
            .map_err(|e| format!("Failed to open file for writing config: {:?}", e))?;
        serde_json::to_writer(&mut file, &config)
            .map_err(|e| format!("Error serializing config: {:?}", e))?;
    }
    if let Some(dump_path) = parse_optional::<PathBuf>(matches, "dump-chain-config")? {
        let chain_config = Config::from_chain_spec::<E>(spec);
        let mut file = std::fs::File::create(dump_path)
            .map_err(|e| format!("Failed to open file for writing chain config: {:?}", e))?;
        serde_yaml::to_writer(&mut file, &chain_config)
            .map_err(|e| format!("Error serializing config: {:?}", e))?;
    }
    Ok(())
}

pub fn get_color_style() -> Styles {
    Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Green.on_default())
}

pub fn parse_flag(matches: &ArgMatches, name: &str) -> bool {
    *matches.get_one::<bool>(name).unwrap_or(&false)
}
