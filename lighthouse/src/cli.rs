use clap::Parser;
use database_manager::cli::DatabaseManager;
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum LighthouseSubcommands {
    DatabaseManager(DatabaseManager),
}
