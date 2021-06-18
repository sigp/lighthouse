#![recursion_limit = "256"]

//! This crate provides a simluation that creates `n` beacon node and validator clients, each with
//! `v` validators. A deposit contract is deployed at the start of the simulation using a local
//! `ganache-cli` instance (you must have `ganache-cli` installed and avaliable on your path). All
//! beacon nodes independently listen for genesis from the deposit contract, then start operating.
//!
//! As the simulation runs, there are checks made to ensure that all components are running
//! correctly. If any of these checks fail, the simulation will exit immediately.
//!
//! ## Future works
//!
//! Presently all the beacon nodes and validator clients all log to stdout. Additionally, the
//! simulation uses `println` to communicate some info. It might be nice if the nodes logged to
//! easy-to-find files and stdout only contained info from the simulation.
//!

#[macro_use]
extern crate clap;

mod checks;
mod cli;
mod eth1_sim;
mod local_network;
mod no_eth1_sim;
mod sync_sim;

use cli::cli_app;
use env_logger::{Builder, Env};
use local_network::LocalNetwork;
use types::MinimalEthSpec;

pub type E = MinimalEthSpec;

fn main() {
    // Debugging output for libp2p and external crates.
    Builder::from_env(Env::default()).init();

    let matches = cli_app().get_matches();
    match matches.subcommand() {
        ("eth1-sim", Some(matches)) => match eth1_sim::run_eth1_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        ("no-eth1-sim", Some(matches)) => match no_eth1_sim::run_no_eth1_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        ("syncing-sim", Some(matches)) => match sync_sim::run_syncing_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        _ => {
            eprintln!("Invalid subcommand. Use --help to see available options");
            std::process::exit(1)
        }
    }
}
