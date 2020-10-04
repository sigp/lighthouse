pub mod create;
pub mod list;
pub mod recover;

use crate::{
    common::{base_wallet_dir, ensure_dir_exists},
    BASE_DIR_FLAG,
};
use clap::{App, Arg, ArgMatches};

pub const CMD: &str = "wallet";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Manage wallets, from which validator keys can be derived.")
        .arg(
            Arg::with_name(BASE_DIR_FLAG)
                .long(BASE_DIR_FLAG)
                .value_name("BASE_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/wallets")
                .takes_value(true),
        )
        .subcommand(create::cli_app())
        .subcommand(list::cli_app())
        .subcommand(recover::cli_app())
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let base_dir = base_wallet_dir(matches, BASE_DIR_FLAG)?;
    ensure_dir_exists(&base_dir)?;

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run(matches, base_dir),
        (list::CMD, Some(_)) => list::cli_run(base_dir),
        (recover::CMD, Some(matches)) => recover::cli_run(matches, base_dir),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
