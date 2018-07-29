#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate clap;
extern crate libp2p_peerstore;

pub mod p2p;
pub mod pubkeystore;
pub mod state;
pub mod utils;

use slog::Drain;
use clap::{ App, SubCommand};
use p2p::config::NetworkConfig;
use p2p::floodsub;
use p2p::state::NetworkState;

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version("0.0.1")
        .author("Paul H. <paul@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .subcommand(SubCommand::with_name("generate-keys"))
            .about("Generates a new set of random keys for p2p dev.")
        .get_matches();

    let config = NetworkConfig::default();
    if let Some(_) = matches.subcommand_matches("generate-keys") {
        // keys::generate_keys(&log).expect("Failed to generate keys");
    } else {
        let state = NetworkState::new(&config).expect("setup failed");
        floodsub::listen(state, &log);
    }
    info!(log, "Exiting.");
}
