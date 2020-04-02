use clap::ArgMatches;
use hex;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::Address;

pub fn time_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("Unable to get time: {:?}", e))
}

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

pub fn parse_u64(matches: &ArgMatches, name: &'static str) -> Result<u64, String> {
    matches
        .value_of(name)
        .ok_or_else(|| format!("{} not specified", name))?
        .parse::<u64>()
        .map_err(|e| format!("Unable to parse {}: {}", name, e))
}

pub fn parse_u64_opt(matches: &ArgMatches, name: &'static str) -> Result<Option<u64>, String> {
    matches
        .value_of(name)
        .map(|val| {
            val.parse::<u64>()
                .map_err(|e| format!("Unable to parse {}: {}", name, e))
        })
        .transpose()
}

pub fn parse_address(matches: &ArgMatches, name: &'static str) -> Result<Address, String> {
    matches
        .value_of(name)
        .ok_or_else(|| format!("{} not specified", name))
        .and_then(|val| {
            if val.starts_with("0x") {
                val[2..]
                    .parse()
                    .map_err(|e| format!("Unable to parse {}: {:?}", name, e))
            } else {
                Err(format!("Unable to parse {}, must have 0x prefix", name))
            }
        })
}

pub fn parse_fork_opt(matches: &ArgMatches, name: &'static str) -> Result<Option<[u8; 4]>, String> {
    matches
        .value_of(name)
        .map(|val| {
            if val.starts_with("0x") {
                let vec = hex::decode(&val[2..])
                    .map_err(|e| format!("Unable to parse {} as hex: {:?}", name, e))?;

                if vec.len() != 4 {
                    Err(format!("{} must be exactly 4 bytes", name))
                } else {
                    let mut arr = [0; 4];
                    arr.copy_from_slice(&vec);
                    Ok(arr)
                }
            } else {
                Err(format!("Unable to parse {}, must have 0x prefix", name))
            }
        })
        .transpose()
}

pub fn parse_hex_bytes(matches: &ArgMatches, name: &'static str) -> Result<Vec<u8>, String> {
    matches
        .value_of(name)
        .ok_or_else(|| format!("{} not specified", name))
        .and_then(|val| {
            if val.starts_with("0x") {
                hex::decode(&val[2..]).map_err(|e| format!("Unable to parse {}: {:?}", name, e))
            } else {
                Err(format!("Unable to parse {}, must have 0x prefix", name))
            }
        })
}
