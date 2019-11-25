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
                        .arg(
                            Arg::with_name("send-deposits")
                                .long("send-deposits")
                                .help("If present, submit validator deposits to an eth1 endpoint")
                        )
                        .arg(
                            Arg::with_name("eth1-endpoint")
                                .short("e")
                                .long("eth1-endpoint")
                                .value_name("HTTP_SERVER")
                                .takes_value(true)
                                .requires("send-deposits")
                                .default_value("http://localhost:8545")
                                .help("The URL to the eth1 JSON-RPC http API."),
                        )
                        .arg(
                            Arg::with_name("deposit-contract")
                                .short("c")
                                .long("deposit-contract")
                                .value_name("ADDRESS")
                                .takes_value(true)
                                .requires("send-deposits")
                                .conflicts_with("testnet-dir")
                                .help("The deposit contract for submitting deposits."),
                        )
                        .arg(
                            Arg::with_name("account-index")
                                .short("i")
                                .long("account-index")
                                .value_name("INDEX")
                                .takes_value(true)
                                .requires("send-deposits")
                                .default_value("0")
                                .help("The eth1 accounts[] index which will send the transaction"),
                        )
                        .arg(
                            Arg::with_name("password")
                                .short("p")
                                .long("password")
                                .value_name("FILE")
                                .takes_value(true)
                                .requires("send-deposits")
                                .help("The password file to unlock the eth1 account (see --index)"),
                        )
                        .arg(
                            Arg::with_name("testnet-dir")
                                .long("testnet-dir")
                                .value_name("DIRECTORY")
                                .takes_value(true)
                                .requires("send-deposits")
                                .default_value("0")
                                .help("The directory from which to read the deposit contract address."),
                        )
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
                                        .help("Index of the last validator")
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
}
