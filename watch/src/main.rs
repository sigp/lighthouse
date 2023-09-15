#[cfg(unix)]
use std::process;

#[cfg(unix)]
mod block_packing;
#[cfg(unix)]
mod block_rewards;
#[cfg(unix)]
mod blockprint;
#[cfg(unix)]
mod cli;
#[cfg(unix)]
mod config;
#[cfg(unix)]
mod database;
#[cfg(unix)]
mod logger;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod suboptimal_attestations;
#[cfg(unix)]
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
