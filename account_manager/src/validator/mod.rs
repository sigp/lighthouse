pub mod create;
pub mod deposit;
pub mod import;
pub mod list;

use crate::BASE_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{custom_base_dir, DEFAULT_WALLET_DIR};
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Provides commands for managing Eth2 validators.")
        .arg(
            Arg::with_name(BASE_DIR_FLAG)
                .long(BASE_DIR_FLAG)
                .value_name(BASE_DIR_FLAG)
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{testnet}/wallets")
                .takes_value(true),
        )
        .subcommand(create::cli_app())
        .subcommand(deposit::cli_app())
        .subcommand(import::cli_app())
        .subcommand(list::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let base_wallet_dir = custom_base_dir(matches, BASE_DIR_FLAG, DEFAULT_WALLET_DIR)?;

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, env, base_wallet_dir),
        (deposit::CMD, Some(matches)) => deposit::cli_run::<T>(matches, env),
        (import::CMD, Some(matches)) => import::cli_run(matches),
        (list::CMD, Some(matches)) => list::cli_run(matches),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
