pub mod create;
pub mod list;

use crate::WALLETS_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{custom_base_dir, ensure_dir_exists, DEFAULT_WALLET_DIR};
use std::path::PathBuf;

pub const CMD: &str = "wallet";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Manage wallets, from which validator keys can be derived.")
        .arg(
            Arg::with_name(WALLETS_DIR_FLAG)
                .long(WALLETS_DIR_FLAG)
                .value_name("BASE_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{testnet}/wallets")
                .takes_value(true)
                .conflicts_with("datadir"),
        )
        .subcommand(create::cli_app())
        .subcommand(list::cli_app())
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        custom_base_dir(matches, WALLETS_DIR_FLAG, DEFAULT_WALLET_DIR)?
    };
    ensure_dir_exists(&base_dir)?;

    eprintln!("wallet-dir path: {:?}", base_dir);

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run(matches, base_dir),
        (list::CMD, Some(_)) => list::cli_run(base_dir),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
