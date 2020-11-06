use clap::{App, Arg};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    // Parse the CLI parameters.
    App::new("remote_signer")
        .visible_alias("rs")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .setting(clap::AppSettings::ColoredHelp)
        .about(
            "Simple HTTP BLS signer service. \
            This service is designed to be consumed by Ethereum 2.0 clients, \
            looking for a more secure avenue to store their BLS12-381 secret keys, \
            while running their validators in more permisive and/or scalable environments.",
        )
        .arg(
            Arg::with_name("storage-raw-dir")
                .long("storage-raw-dir")
                .value_name("DIR")
                .help("Data directory for secret keys in raw files."),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address to listen for TCP connections.")
                .default_value("0.0.0.0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP port to listen on.")
                .default_value("9000")
                .takes_value(true),
        )
}
