pub mod create;
pub mod list;
pub mod recover;

use crate::WALLETS_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{ensure_dir_exists, parse_path_or_default_with_flag, DEFAULT_WALLET_DIR};
use std::path::PathBuf;

pub const CMD: &str = "wallet";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Manage wallets, from which validator keys can be derived.")
        .arg(
            Arg::with_name(WALLETS_DIR_FLAG)
                .long(WALLETS_DIR_FLAG)
                .value_name("WALLETS_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets")
                .takes_value(true)
                .conflicts_with("datadir"),
        )
        .subcommand(create::cli_app())
        .subcommand(list::cli_app())
        .subcommand(recover::cli_app())
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let wallet_base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, WALLETS_DIR_FLAG, DEFAULT_WALLET_DIR)?
    };
    ensure_dir_exists(&wallet_base_dir)?;

    eprintln!("wallet-dir path: {:?}", wallet_base_dir);

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run(matches, wallet_base_dir),
        (list::CMD, Some(_)) => list::cli_run(wallet_base_dir),
        (recover::CMD, Some(matches)) => recover::cli_run(matches, wallet_base_dir),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
