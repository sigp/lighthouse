use crate::config::Config;
use clap::{App, Arg, SubCommand};
use lazy_static::lazy_static;

lazy_static! {
    /// The default configuration. Is in lazy_static because clap requires references, therefore we
    /// can't initialize the defaults in the `cli_app` function
    static ref DEFAULTS: Config = {
        Config::default()
    };

    static ref DEFAULT_SERVER_HTTP_PORT: String = {
        format!("{}", DEFAULTS.server_http_port)
    };
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("Validator Client")
        .visible_aliases(&["v", "vc", "validator", "validator_client"])
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Validator Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("logfile")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eth2-config")
                .long("eth2-config")
                .short("e")
                .value_name("TOML_FILE")
                .help("Path to Ethereum 2.0 config and specification file (e.g., eth2_spec.toml).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("NETWORK_ADDRESS")
                .help("Address to connect to BeaconNode.")
                .default_value(&DEFAULTS.server)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server-http-port")
                .long("server-http-port")
                .short("h")
                .value_name("PORT")
                .help("Port to use for HTTP API connection to the server.")
                .default_value(&DEFAULT_SERVER_HTTP_PORT)
                .takes_value(true),
        )
        /*
         * The "testnet" sub-command.
         *
         * Used for starting testnet validator clients.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Starts a testnet validator using INSECURE, predicatable private keys, based off the canonical \
                   validator index. ONLY USE FOR TESTING PURPOSES!")
            .arg(
                Arg::with_name("bootstrap")
                    .short("b")
                    .long("bootstrap")
                    .help("Connect to the RPC server to download the eth2_config via the HTTP API.")
            )
            .subcommand(SubCommand::with_name("insecure")
                .about("Uses the standard, predicatable `interop` keygen method to produce a range \
                        of predicatable private keys and starts performing their validator duties.")
                .arg(Arg::with_name("first_validator")
                    .value_name("VALIDATOR_INDEX")
                    .required(true)
                    .help("The first validator public key to be generated for this client."))
                .arg(Arg::with_name("last_validator")
                    .value_name("VALIDATOR_INDEX")
                    .required(true)
                    .help("The end of the range of keys to generate. This index is not generated."))
            )
            .subcommand(SubCommand::with_name("interop-yaml")
                .about("Loads plain-text secret keys from YAML files. Expects the interop format defined
                       in the ethereum/eth2.0-pm repo.")
                .arg(Arg::with_name("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Path to a YAML file."))
            )
        )
        .subcommand(SubCommand::with_name("sign_block")
            .about("Connects to the beacon server, requests a new block (after providing reveal),\
            and prints the signed block to standard out")
            .arg(Arg::with_name("validator")
                .value_name("VALIDATOR")
                .required(true)
                .help("The pubkey of the validator that should sign the block.")
            )
        )
}
