use env_logger::Builder;
use log::error;
use std::process;

mod cli;
mod database;
mod server;
mod update_service;

#[tokio::main]
async fn main() {
    Builder::from_default_env().init();

    match cli::run().await {
        Ok(()) => process::exit(0),
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("{}", e);
            drop(e);
            process::exit(1)
        }
    }
}
