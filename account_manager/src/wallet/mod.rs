pub mod cli;
pub mod create;
pub mod list;
pub mod recover;

use crate::WALLETS_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{ensure_dir_exists, parse_path_or_default_with_flag, DEFAULT_WALLET_DIR};
use std::path::PathBuf;
use clap_utils::GlobalConfig;
use crate::wallet::cli::WalletSubcommand;

pub const CMD: &str = "wallet";

pub fn cli_run(wallet_config: &cli::Wallet, global_config: &GlobalConfig) -> Result<(), String> {
    let wallet_base_dir = if let Some(wallet_dir) = global_config.datadir.as_ref() {
        wallet_dir.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(wallet_config.wallets_dir.clone(), global_config, DEFAULT_WALLET_DIR)?
    };
    ensure_dir_exists(&wallet_base_dir)?;

    eprintln!("wallet-dir path: {:?}", wallet_base_dir);

    match &wallet_config.subcommand {
        WalletSubcommand::Create(create_config) =>  create::cli_run(&create_config, wallet_base_dir),
        WalletSubcommand::List(_) =>  list::cli_run(wallet_base_dir),
        WalletSubcommand::Recover(recover_config) =>  recover::cli_run(&recover_config, wallet_base_dir),
    }
}
