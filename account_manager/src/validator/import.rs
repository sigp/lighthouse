use crate::{common::ensure_dir_exists, VALIDATOR_DIR_FLAG};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "import";
pub const KEYSTORE_FLAG: &str = "keystore";
pub const DIR_FLAG: &str = "directory";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Reads existing EIP-2335 keystores and imports them into a Lighthouse \
            validator client.",
        )
        .arg(
            Arg::with_name(KEYSTORE_FLAG)
                .long(KEYSTORE_FLAG)
                .value_name("KEYSTORE_PATH")
                .help("Path to a single keystore to be imported.")
                .conflicts_with(DIR_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DIR_FLAG)
                .long(DIR_FLAG)
                .value_name("KEYSTORES_DIRECTORY")
                .help(
                    "Path to a directory which contains zero or more keystores \
                    for import. This directory and all sub-directories will be \
                    searched and any file name which contains 'keystore' and \
                    has the '.json' extension will be attempted to be imported.",
                )
                .conflicts_with(KEYSTORE_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                    Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
}

pub fn cli_run(matches: &ArgMatches, wallet_base_dir: PathBuf) -> Result<(), String> {
    let keystore: Option<PathBuf> = clap_utils::parse_optional(matches, KEYSTORE_FLAG)?;
    let keystores_dir: Option<PathBuf> = clap_utils::parse_optional(matches, DIR_FLAG)?;
    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;

    ensure_dir_exists(&validator_dir)?;

    let keystores = match (keystore, keystores_dir) {
        (Some(keystore), None) => vec![keystore],
        (None, Some(keystores_dir)) => todo!("recursive search"),
        _ => {
            return Err(format!(
                "Must supply either --{} or --{}",
                KEYSTORE_FLAG, DIR_FLAG
            ))
        }
    };

    todo!()
}
