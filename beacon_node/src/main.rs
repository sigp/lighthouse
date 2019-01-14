extern crate slog;

mod config;
mod rpc;

use std::path::PathBuf;

use crate::config::LighthouseConfig;
use crate::rpc::start_server;
use clap::{App, Arg};
use slog::{error, info, o, Drain};

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version("0.0.1")
        .author("Sigma Prime <paul@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Network listen port for p2p connections.")
                .takes_value(true),
        )
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

    let _server = start_server(log.clone());

    loop {}

    // info!(log, "Exiting.");
}
