//! A helper library for parsing values from `clap::ArgMatches`.

use clap::ArgMatches;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use ethereum_types::U256 as Uint256;
pub use serde_yaml::Value as YamlValue;
use ssz::Decode;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
pub use toml::Value as TomlValue;

pub use default_config::DefaultConfigApp;

mod default_config;
#[macro_use]
pub mod flags;
#[macro_use]
pub mod lcli_flags;

pub const BAD_TESTNET_DIR_MESSAGE: &str = "The hard-coded testnet directory was invalid. \
                                        This happens when Lighthouse is migrating between spec versions \
                                        or when there is no default public network to connect to. \
                                        During these times you must specify a --testnet-dir.";

/// Try to parse the eth2 network config from the `network`, `testnet-dir` flags in that order.
/// Returns the default hardcoded testnet if neither flags are set.
pub fn get_eth2_network_config(cli_args: &ArgMatches) -> Result<Eth2NetworkConfig, String> {
    let optional_network_config = if cli_args.is_present("network") {
        parse_hardcoded_network(cli_args, "network")?
    } else if cli_args.is_present("testnet-dir") {
        parse_testnet_dir(cli_args, "testnet-dir")?
    } else {
        // if neither is present, assume the default network
        Eth2NetworkConfig::constant(DEFAULT_HARDCODED_NETWORK)?
    };

    let mut eth2_network_config =
        optional_network_config.ok_or_else(|| BAD_TESTNET_DIR_MESSAGE.to_string())?;

    if let Some(string) = parse_optional::<String>(cli_args, "terminal-total-difficulty-override")?
    {
        let stripped = string.replace(",", "");
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
        .value_of(name)
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

/// Attempts to parse a file into a `HashMap<String,String>`. Requires the filename end in `.yaml`/`.yml`
/// for a YAML config file or `.toml` for a TOML config file.
pub fn parse_file_config(file_name: &str) -> Result<HashMap<String, String>, String> {
    if file_name.ends_with(".yaml") || file_name.ends_with(".yml") {
        fs::read_to_string(file_name)
            .map_err(|e| e.to_string())
            .and_then(|yaml| serde_yaml::from_str(yaml.as_str()).map_err(|e| e.to_string()))
            .and_then(|parsed| to_string_map(parsed, yaml_value_to_string))
    } else if file_name.ends_with(".toml") {
        fs::read_to_string(file_name)
            .map_err(|e| e.to_string())
            .and_then(|toml| toml::from_str(toml.as_str()).map_err(|e| e.to_string()))
            .and_then(|parsed| to_string_map(parsed, toml_value_to_string))
    } else {
        Err("config file must have extension `.yml`, `.yaml` or `.toml`".to_string())
    }
}

pub fn to_string_map<V, F: Fn(V) -> Result<String, String>>(
    map: HashMap<String, V>,
    f: F,
) -> Result<HashMap<String, String>, String> {
    let mut new_map = HashMap::new();
    for (key, value) in map.into_iter() {
        new_map.insert(key, f(value)?);
    }
    Ok(new_map)
}

pub fn toml_value_to_string(value: TomlValue) -> Result<String, String> {
    let string_value = match value {
        TomlValue::String(v) => v,
        TomlValue::Integer(v) => v.to_string(),
        TomlValue::Float(v) => v.to_string(),
        TomlValue::Boolean(v) => v.to_string(),
        TomlValue::Datetime(v) => v.to_string(),
        TomlValue::Array(v) => v
            .into_iter()
            .map(toml_value_to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        TomlValue::Table(_) => return Err("Unable to parse YAML table".to_string()),
    };
    Ok(string_value)
}

fn yaml_value_to_string(value: YamlValue) -> Result<String, String> {
    let string_value = match value {
        YamlValue::String(v) => v,
        YamlValue::Null => "".to_string(),
        YamlValue::Bool(v) => v.to_string(),
        YamlValue::Number(v) => v.to_string(),
        YamlValue::Sequence(v) => v
            .into_iter()
            .map(yaml_value_to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        YamlValue::Mapping(_) => return Err("Unable to parse TOML table".to_string()),
    };
    Ok(string_value)
}
