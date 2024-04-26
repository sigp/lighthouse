//! This crate provides various simulations that create both beacon nodes and validator clients,
//! each with `v` validators.
//!
//! When a simulation runs, there are checks made to ensure that all components are operating
//! as expected. If any of these checks fail, the simulation will exit immediately.
//!
//! ## Future works
//!
//! Presently all the beacon nodes and validator clients all log to stdout. Additionally, the
//! simulation uses `println` to communicate some info. It might be nice if the nodes logged to
//! easy-to-find files and stdout only contained info from the simulation.
//!

#[macro_use]
extern crate clap;

mod basic_sim;
mod checks;
mod cli;
mod fallback_sim;
mod local_network;
mod retry;

use cli::cli_app;
use env_logger::{Builder, Env};
use local_network::LocalNetwork;
use types::MinimalEthSpec;

// Since simulator tests are non-deterministic and there is a non-zero chance of missed
// attestations, define an acceptable network-wide attestation performance.
//
// This has potential to block CI so it should be set conservatively enough that spurious failures
// don't become very common, but not so conservatively that regressions to the fallback mechanism
// cannot be detected.
pub(crate) const ACCEPTABLE_FALLBACK_ATTESTATION_HIT_PERCENTAGE: f64 = 95.0;

pub type E = MinimalEthSpec;

fn main() {
    // Debugging output for libp2p and external crates.
    Builder::from_env(Env::default()).init();

    let matches = cli_app().get_matches();
    match matches.subcommand() {
        ("basic-sim", Some(matches)) => match basic_sim::run_basic_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        ("fallback-sim", Some(matches)) => match fallback_sim::run_fallback_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        ("fallback-sim", Some(matches)) => match fallback_sim::run_fallback_sim(matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with an error: {}", e);
                std::process::exit(1)
            }
        },
        _ => {
            eprintln!("Invalid subcommand. Use --help to see available options");
            std::process::exit(1)
        }
    }
}
