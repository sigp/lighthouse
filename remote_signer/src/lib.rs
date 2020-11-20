mod cli;

use clap::ArgMatches;
use client::Client;
use environment::Environment;
use slog::info;
use types::EthSpec;

pub use cli::cli_app;

pub fn run<E: EthSpec>(
    environment: &mut Environment<E>,
    matches: &ArgMatches,
) -> Result<(), String> {
    let context = environment.core_context();
    let exit = context.executor.exit();

    info!(
        context.log(),
        "Starting remote signer";
    );

    let client = environment
        .runtime()
        .block_on(Client::new(context, matches))
        .map_err(|e| format!("Failed to init Rest API: {}", e))?;

    environment.runtime().spawn(async move {
        exit.await;
        drop(client);
    });

    Ok(())
}
