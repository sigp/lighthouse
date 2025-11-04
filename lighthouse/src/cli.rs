use clap::Parser;
use database_manager::cli::DatabaseManager;
use serde::{Deserialize, Serialize};
use validator_client::cli::ValidatorClient;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
pub enum LighthouseSubcommands {
    #[clap(name = "database_manager")]
    DatabaseManager(Box<DatabaseManager>),
    #[clap(name = "validator_client")]
    ValidatorClient(Box<ValidatorClient>),
}
