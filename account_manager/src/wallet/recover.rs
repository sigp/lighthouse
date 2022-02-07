use crate::common::read_mnemonic_from_cli;
use crate::wallet::cli::{NewWallet, Recover};
use std::path::PathBuf;

pub const CMD: &str = "recover";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";

pub fn cli_run(config: &Recover, wallet_base_dir: PathBuf) -> Result<(), String> {
    let mnemonic_path = config.mnemonic.clone();
    let stdin_inputs = cfg!(windows) || config.stdin_inputs;

    eprintln!();
    eprintln!("WARNING: KEY RECOVERY CAN LEAD TO DUPLICATING VALIDATORS KEYS, WHICH CAN LEAD TO SLASHING.");
    eprintln!();

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;

    let wallet = config
        .create_wallet_from_mnemonic(wallet_base_dir.as_path(), &mnemonic)
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
