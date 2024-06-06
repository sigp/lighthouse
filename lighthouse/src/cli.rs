use clap::Parser;
use database_manager::cli::DatabaseManager;
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
pub enum LighthouseSubcommands {
    #[clap(name = "database_manager")]
    DatabaseManager(DatabaseManager),
}
