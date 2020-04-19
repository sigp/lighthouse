//! A helper library for parsing values from `clap::ArgMatches`.

use clap::ArgMatches;
use eth2_testnet_config::Eth2TestnetConfig;
use hex;
use ssz::Decode;
use std::path::PathBuf;
use std::str::FromStr;
use types::EthSpec;

/// Attempts to load the testnet dir at the path if `name` is in `matches`, returning an error if
/// the path cannot be found or the testnet dir is invalid.
///
/// If `name` is not in `matches`, attempts to return the "hard coded" testnet dir.
pub fn parse_testnet_dir_with_hardcoded_default<E: EthSpec>(
    matches: &ArgMatches,
    name: &'static str,
) -> Result<Eth2TestnetConfig<E>, String> {
    parse_required::<PathBuf>(matches, name)
        .and_then(|path| {
            Eth2TestnetConfig::load(path.clone())
                .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", path, e))
        })
        .map(Result::Ok)
        .unwrap_or_else(|_| {
            Eth2TestnetConfig::hard_coded().map_err(|e| {
                format!(
                    "The hard-coded testnet directory was invalid. \
                     This happens when Lighthouse is migrating between spec versions. \
                     Error : {}",
                    e
                )
            })
        })
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
pub fn parse_required<T>(matches: &ArgMatches, name: &'static str) -> Result<T, String>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    parse_optional(matches, name)?.ok_or_else(|| format!("{} not specified", name))
}

/// Returns the value of `name` (if present) or an error if it does not parse successfully using
/// `std::string::FromStr`.
pub fn parse_optional<T>(matches: &ArgMatches, name: &'static str) -> Result<Option<T>, String>
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
            if val.starts_with("0x") {
                let vec = hex::decode(&val[2..])
                    .map_err(|e| format!("Unable to parse {} as hex: {:?}", name, e))?;

                T::from_ssz_bytes(&vec)
                    .map_err(|e| format!("Unable to parse {} as SSZ: {:?}", name, e))
            } else {
                Err(format!("Unable to parse {}, must have 0x prefix", name))
            }
        })
        .transpose()
}
