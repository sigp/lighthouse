mod common;
pub mod validator;
pub mod wallet;

use clap::App;
use clap::ArgMatches;
use clap::{ArgEnum, Args, Subcommand};
pub use clap::{IntoApp, Parser};
use environment::Environment;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use clap_utils::GlobalConfig;
use types::EthSpec;

pub const CMD: &str = "account_manager";
pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "snake_case", visible_aliases = &["a", "am", "account"],
about = "Utilities for generating and managing Ethereum 2.0 accounts.")]
pub enum AccountManager {
    Wallet(wallet::cli::Wallet),
    Validator(validator::cli::Validator),
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<T: EthSpec>(account_manager: &AccountManager, global_config: &GlobalConfig, env: Environment<T>) -> Result<(), String> {
    match account_manager {
        AccountManager::Wallet(wallet) => wallet::cli_run(wallet, global_config)?,
        AccountManager::Validator(validator) => validator::cli_run(validator, global_config, env)?,
        }
    Ok(())
}
