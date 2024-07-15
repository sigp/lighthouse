use crate::WALLETS_DIR_FLAG;
use clap::{Arg, ArgAction, Command};
use clap_utils::FLAG_HEADER;
use eth2_wallet_manager::WalletManager;
use std::path::PathBuf;

pub const CMD: &str = "list";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Lists the names of all wallets.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
}

pub fn cli_run(wallet_base_dir: PathBuf) -> Result<(), String> {
    let mgr = WalletManager::open(wallet_base_dir)
        .map_err(|e| format!("Unable to open --{}: {:?}", WALLETS_DIR_FLAG, e))?;

    for (name, _uuid) in mgr
        .wallets()
        .map_err(|e| format!("Unable to list wallets: {:?}", e))?
    {
        println!("{}", name)
    }

    Ok(())
}
