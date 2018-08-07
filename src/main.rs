#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate clap;
extern crate libp2p_peerstore;
extern crate network_libp2p;

pub mod pubkeystore;
pub mod state;
pub mod sync;
pub mod utils;
pub mod config;

use std::path::PathBuf; 

use slog::Drain;
use clap::{ Arg, App };
use config::LighthouseConfig;
use network_libp2p::service::NetworkService;
use network_libp2p::state::NetworkState;
use sync::sync_start;

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version("0.0.1")
        .author("Sigma Prime <paul@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .arg(Arg::with_name("datadir")
            .long("datadir")
            .value_name("DIR")
            .help("Data directory for keys and databases.")
            .takes_value(true))
        .arg(Arg::with_name("port")
            .long("port")
            .value_name("PORT")
            .help("Network listen port for p2p connections.")
            .takes_value(true))
        .get_matches();

    let mut config = LighthouseConfig::default();

    // Custom datadir
    if let Some(dir) = matches.value_of("datadir") {
        config.data_dir = PathBuf::from(dir.to_string());
    }

    // Custom p2p listen port
    if let Some(port_str) = matches.value_of("port") {
        if let Ok(port) = port_str.parse::<u16>() {
            config.p2p_listen_port = port;
        } else {
            error!(log, "Invalid port"; "port" => port_str);
            return;
        }
    }
    
    // Log configuration
    info!(log, ""; 
          "data_dir" => &config.data_dir.to_str(),
          "port" => &config.p2p_listen_port);
    
    let state = NetworkState::new(
        &config.data_dir,
        &config.p2p_listen_port,
        &log)
        .expect("setup failed");
    let (service, net_rx) = NetworkService::new(state, log.new(o!()));
    sync_start(service, net_rx, log.new(o!()));

    info!(log, "Exiting.");
}
