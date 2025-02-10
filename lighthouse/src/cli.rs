use account_manager::AccountManager;
use clap::Parser;
use database_manager::cli::DatabaseManager;
use serde::{Deserialize, Serialize};
use validator_client::cli::ValidatorClient;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
pub enum LighthouseSubcommands {
    #[clap(name = "database_manager", display_order = 0)]
    DatabaseManager(DatabaseManager),
    #[clap(name = "account_manager", display_order = 0)]
    AccountManager(AccountManager),
    #[clap(name = "validator_client")]
    ValidatorClient(Box<ValidatorClient>),
}
