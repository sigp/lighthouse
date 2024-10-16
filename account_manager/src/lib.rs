mod common;
pub mod validator;
pub mod wallet;

use clap::ArgMatches;
use clap::Parser;
use environment::Environment;
use serde::Deserialize;
use serde::Serialize;
use types::EthSpec;

pub const CMD: &str = "account_manager";
pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
pub const VALIDATOR_DIR_FLAG_ALIAS: &str = "validators-dir";
pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

#[derive(Clone, Deserialize, Serialize, Debug, Parser)]
#[clap(visible_aliases = &["a", "am", "account"], about = "Utilities for generating and managing Ethereum 2.0 accounts.")]
pub struct AccountManager {
    #[clap(subcommand)]
    pub subcommand: AccountManagerSubcommand,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum AccountManagerSubcommand {
    Wallet(wallet::cli::Wallet),
    Validator(validator::cli::Validator),
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<E: EthSpec>(
    account_manager: &AccountManager,
    matches: &ArgMatches,
    env: Environment<E>,
) -> Result<(), String> {
    match &account_manager.subcommand {
        AccountManagerSubcommand::Wallet(wallet_config) => wallet::cli_run(wallet_config, matches)?,
        AccountManagerSubcommand::Validator(validator_config) => {
            validator::cli_run(validator_config, matches, env)?
        }
    }

    Ok(())
}
