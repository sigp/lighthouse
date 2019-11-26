use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("account_manager")
        .visible_aliases(&["a", "am", "account", "account_manager"])
        .about("Utilities for generating and managing Ethereum 2.0 accounts.")
        .subcommand(
            SubCommand::with_name("validator")
                .about("Generate or manage Etheruem 2.0 validators.")
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Create a new Ethereum 2.0 validator.")
                        .subcommand(
                            SubCommand::with_name("insecure")
                                .about("Produce insecure, ephemeral validators. DO NOT USE TO STORE VALUE.")
                                .arg(
                                    Arg::with_name("first")
                                        .index(1)
                                        .value_name("INDEX")
                                        .help("Index of the first validator")
                                        .takes_value(true)
                                        .required(true),
                                )
                                .arg(
                                    Arg::with_name("last")
                                        .index(2)
                                        .value_name("INDEX")
                                        .help("Index of the first validator")
                                        .takes_value(true)
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            SubCommand::with_name("random")
                                .about("Produces public keys using entropy from the Rust 'rand' library.")
                                .arg(
                                    Arg::with_name("validator_count")
                                        .index(1)
                                        .value_name("INTEGER")
                                        .help("The number of new validators to generate.")
                                        .takes_value(true)
                                        .default_value("1"),
                                ),
                        )
                )
        )
        .subcommand(
            SubCommand::with_name("generate_deposit_keystores")
                .about("Generates and saves validator and withdrawal keystores and generates deposit parameters from them")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>")
                .arg(
                    Arg::with_name("deposit_amount")
                        .long("deposit_amount")
                        .short("d")
                        .value_name("deposit_amount")
                        .help("The amount being deposited in GWEI")
                        .takes_value(true)
                        .required(true),
                )
        )
}
