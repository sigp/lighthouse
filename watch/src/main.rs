use std::process;

mod block_packing;
mod block_rewards;
mod blockprint;
mod cli;
mod config;
mod database;
mod logger;
mod server;
mod suboptimal_attestations;
mod updater;

#[cfg(unix)]
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

#[cfg(windows)]
fn main() {
    eprintln!("Windows is not supported. Exiting.");
}
