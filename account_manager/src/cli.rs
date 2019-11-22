use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("Account Manager")
        .visible_aliases(&["am", "accounts", "accounts_manager"])
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Accounts Manager")
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("logfile")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generates a new validator private key")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>"),
        )
        .subcommand(
            SubCommand::with_name("generate_deterministic")
                .about("Generates a deterministic validator private key FOR TESTING")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>")
                .arg(
                    Arg::with_name("validator index")
                        .long("index")
                        .short("i")
                        .value_name("index")
                        .help("The index of the validator, for which the test key is generated")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("validator count")
                        .long("validator_count")
                        .short("n")
                        .value_name("validator_count")
                        .help("If supplied along with `index`, generates keys `i..i + n`.")
                        .takes_value(true)
                        .default_value("1"),
                ),
        )
}
