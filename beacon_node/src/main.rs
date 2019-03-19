extern crate slog;

mod run;

use clap::{App, Arg};
use client::ClientConfig;
use slog::{error, o, Drain};

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version(version::version().as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_address")
                .long("listen_address")
                .value_name("Listen Address")
                .help("The Network address to listen for p2p connections.")
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

    // invalid arguments, panic
    let config = ClientConfig::parse_args(matches, &logger).unwrap();

    match run::run_beacon_node(config, &logger) {
        Ok(_) => {}
        Err(e) => error!(logger, "Beacon node failed because {:?}", e),
    }
}
