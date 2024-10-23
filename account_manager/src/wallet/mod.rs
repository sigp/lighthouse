pub mod cli;
pub mod create;
pub mod list;
pub mod recover;

use clap::ArgMatches;
use cli::Wallet;
use directory::{ensure_dir_exists, parse_path_or_default_with_flag_v2, DEFAULT_WALLET_DIR};
use std::path::PathBuf;

pub const CMD: &str = "wallet";

pub fn cli_run(wallet_config: &Wallet, matches: &ArgMatches) -> Result<(), String> {
    let wallet_base_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag_v2(
            matches,
            wallet_config.wallets_dir.clone(),
            DEFAULT_WALLET_DIR,
        )?
    };
    ensure_dir_exists(&wallet_base_dir)?;

    eprintln!("wallet-dir path: {:?}", wallet_base_dir);

    match &wallet_config.subcommand {
        cli::WalletSubcommand::Create(create_config) => {
            create::cli_run(create_config, matches, wallet_base_dir)
        }
        cli::WalletSubcommand::List(_) => list::cli_run(wallet_base_dir),
        cli::WalletSubcommand::Recover(recover_config) => {
            recover::cli_run(recover_config, matches, wallet_base_dir)
        }
    }
}
