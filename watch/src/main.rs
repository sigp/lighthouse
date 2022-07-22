use std::process;

mod cli;
mod config;
mod database;
mod logger;
mod server;
mod updater;

#[tokio::main]
async fn main() {
    match cli::run().await {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("Command failed with: {}", e);
            drop(e);
            process::exit(1)
        }
    }
}
