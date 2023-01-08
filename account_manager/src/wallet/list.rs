use crate::WALLETS_DIR_FLAG;
use clap::App;
use eth2_wallet_manager::WalletManager;
use std::path::PathBuf;

pub const CMD: &str = "list";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD).about("Lists the names of all wallets.")
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
