mod create;
mod validator;

use clap::{App, Arg, ArgMatches};
use clap_utils;
use environment::Environment;
use eth2_wallet::PlainText;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use types::EthSpec;

pub const CMD: &str = "wallet";

/// The `Alphanumeric` crate only generates a-Z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("TODO")
        .arg(
            Arg::with_name("base-dir")
                .long("base-dir")
                .value_name("BASE_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/wallets")
                .takes_value(true),
        )
        .subcommand(create::cli_app())
        .subcommand(validator::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let base_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "base-dir",
        PathBuf::new().join(".lighthouse").join("wallets"),
    )?;

    ensure_dir_exists(&base_dir)?;

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, base_dir),
        (validator::CMD, Some(matches)) => validator::cli_run::<T>(matches, env, base_dir),
        (unknown, _) => {
            return Err(format!(
                "{} does not have a {} command. See --help",
                CMD, unknown
            ));
        }
    }
}

fn random_password() -> PlainText {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .collect::<String>()
        .into_bytes()
        .into()
}

fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let path = path.as_ref();

    if !path.exists() {
        create_dir_all(path).map_err(|e| format!("Unable to create {:?}: {:?}", path, e))?;
    }

    Ok(())
}
