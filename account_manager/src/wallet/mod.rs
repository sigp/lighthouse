pub mod create;
pub mod list;
pub mod recover;

use crate::WALLETS_DIR_FLAG;
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use directory::{ensure_dir_exists, parse_path_or_default_with_flag, DEFAULT_WALLET_DIR};
use std::path::PathBuf;

pub const CMD: &str = "wallet";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Manage wallets, from which validator keys can be derived.")
        .display_order(0)
        .arg(
            Arg::new("help")
            .long("help")
            .short('h')
            .help("Prints help information")
            .action(ArgAction::HelpLong)
            .display_order(0)
            .help_heading(FLAG_HEADER)
        )
        .arg(
            Arg::new(WALLETS_DIR_FLAG)
                .long(WALLETS_DIR_FLAG)
                .value_name("WALLETS_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets")
                .action(ArgAction::Set)
                .conflicts_with("datadir"),
        )
        .subcommand(create::cli_app())
        .subcommand(list::cli_app())
        .subcommand(recover::cli_app())
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let wallet_base_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, WALLETS_DIR_FLAG, DEFAULT_WALLET_DIR)?
    };
    ensure_dir_exists(&wallet_base_dir)?;

    eprintln!("wallet-dir path: {:?}", wallet_base_dir);

    match matches.subcommand() {
        Some((create::CMD, matches)) => create::cli_run(matches, wallet_base_dir),
        Some((list::CMD, _)) => list::cli_run(wallet_base_dir),
        Some((recover::CMD, matches)) => recover::cli_run(matches, wallet_base_dir),
        Some((unknown, _)) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
        _ => Err("No subcommand provided, see --help for options".to_string()),
    }
}
