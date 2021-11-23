use database::{Config, Database, Error};
use env_logger::Builder;
use log::error;
use std::process::exit;

mod cli;
mod database;
mod update_service;

#[tokio::main]
async fn main() {
    Builder::from_default_env().init();

    match cli::run().await {
        Ok(()) => exit(0),
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("{}", e);
            drop(e);
            exit(1)
        }
    }
}
