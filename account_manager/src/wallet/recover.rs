use crate::wallet::cli::NewWallet;
use account_utils::{read_mnemonic_from_cli, STDIN_INPUTS_FLAG};
use clap::ArgMatches;
use std::path::PathBuf;

use super::cli::Recover;

pub const CMD: &str = "recover";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";

pub fn cli_run(
    recover_config: &Recover,
    matches: &ArgMatches,
    wallet_base_dir: PathBuf,
) -> Result<(), String> {
    let mnemonic_path = recover_config.mnemonic_path.clone();
    let stdin_inputs = cfg!(windows) || matches.get_flag(STDIN_INPUTS_FLAG);

    eprintln!();
    eprintln!("WARNING: KEY RECOVERY CAN LEAD TO DUPLICATING VALIDATORS KEYS, WHICH CAN LEAD TO SLASHING.");
    eprintln!();

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;

    let wallet = recover_config
        .create_wallet_from_mnemonic(wallet_base_dir.as_path(), matches, &mnemonic)
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    println!("Your wallet has been successfully recovered.");
    println!();
    println!("Your wallet's UUID is:");
    println!();
    println!("\t{}", wallet.wallet().uuid());
    println!();
    println!("You do not need to backup your UUID or keep it secret.");

    Ok(())
}
